package aimonitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// openAICompatClient talks to an OpenAI-compatible chat completions API: the
// OpenAI API itself, or a local server such as Ollama, LM Studio or vLLM. A
// local model keeps the events Rig reviews on your machine.
type openAICompatClient struct {
	endpoint string
	model    string
	apiKey   string
	http     *http.Client
}

func newOpenAICompatClient(cfg Config) *openAICompatClient {
	endpoint := cfg.Endpoint
	if endpoint == "" {
		endpoint = "https://api.openai.com/v1"
		if cfg.Provider == "ollama" {
			endpoint = "http://127.0.0.1:11434/v1"
		}
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 2 * time.Minute}
	}
	return &openAICompatClient{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		model:    cfg.Model,
		apiKey:   cfg.APIKey,
		http:     client,
	}
}

func (c *openAICompatClient) Review(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"response_format": map[string]string{"type": "json_object"},
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned %s: %s", c.endpoint, resp.Status, clip(strings.TrimSpace(string(data)), 200))
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil || len(parsed.Choices) == 0 {
		return "", fmt.Errorf("unexpected reply from %s", c.endpoint)
	}
	return parsed.Choices[0].Message.Content, nil
}
