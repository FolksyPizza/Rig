package aimonitor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/anthropics/anthropic-sdk-go/v2/option"
	"github.com/anthropics/anthropic-sdk-go/v2/shared/constant"
)

// verdictSchema constrains the model's reply to a Verdict.
var verdictSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"risk":     map[string]any{"type": "string", "enum": []string{"none", "low", "medium", "high", "critical"}},
		"summary":  map[string]any{"type": "string"},
		"evidence": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
	},
	"required":             []string{"risk", "summary", "evidence"},
	"additionalProperties": false,
}

type anthropicClient struct {
	client    anthropic.Client
	model     string
	fallbacks bool
	effort    bool
}

// Models that accept server-side refusal fallbacks ("default" routing) on
// the Claude API. Security logs read like attack traffic, so a safety
// classifier may decline to review one; a fallback keeps the review going.
var fallbackModels = map[string]bool{
	"claude-opus-5-5":   true,
	"claude-opus-5":     true,
	"claude-fable-5-1":  true,
	"claude-sonnet-5-5": true,
}

func supportsEffort(model string) bool {
	for _, p := range []string{"claude-opus-5", "claude-opus-4-8", "claude-opus-4-7", "claude-opus-4-6", "claude-sonnet-5", "claude-haiku-5", "claude-fable-", "claude-mythos-"} {
		if strings.HasPrefix(model, p) {
			return true
		}
	}
	return false
}

func newAnthropicClient(cfg Config) *anthropicClient {
	opts := []option.RequestOption{
		option.WithMaxRetries(2),
		option.WithRequestTimeout(90 * time.Second),
	}
	if cfg.APIKey != "" {
		opts = append(opts, option.WithAPIKey(cfg.APIKey))
	}
	if cfg.Endpoint != "" {
		opts = append(opts, option.WithBaseURL(cfg.Endpoint))
	}
	return &anthropicClient{
		client:    anthropic.NewClient(opts...),
		model:     cfg.Model,
		fallbacks: cfg.Endpoint == "" && fallbackModels[cfg.Model],
		effort:    supportsEffort(cfg.Model),
	}
}

// errRefused reports a safety decline; the review is skipped, never treated
// as a clean bill of health.
var errRefused = errors.New("the model declined to review this batch")

func (c *anthropicClient) Review(ctx context.Context, system, user string) (string, error) {
	params := anthropic.BetaMessageNewParams{
		Model:     anthropic.Model(c.model),
		MaxTokens: 8192,
		System:    []anthropic.BetaTextBlockParam{{Text: system}},
		Messages: []anthropic.BetaMessageParam{
			anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(user)),
		},
		OutputConfig: anthropic.BetaOutputConfigParam{
			Format: anthropic.BetaJSONOutputFormatParam{Schema: verdictSchema},
		},
	}
	if c.effort {
		params.OutputConfig.Effort = anthropic.BetaOutputConfigEffortMedium
	}
	if c.fallbacks {
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()}
	}

	resp, err := c.client.Beta.Messages.New(ctx, params)
	if err != nil {
		return "", err
	}
	switch resp.StopReason {
	case anthropic.BetaStopReasonRefusal:
		return "", errRefused
	case anthropic.BetaStopReasonMaxTokens:
		return "", fmt.Errorf("the reply was cut off at the token limit")
	}
	var text strings.Builder
	for _, block := range resp.Content {
		if b, ok := block.AsAny().(anthropic.BetaTextBlock); ok {
			text.WriteString(b.Text)
		}
	}
	return text.String(), nil
}
