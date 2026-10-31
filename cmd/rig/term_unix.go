//go:build unix

package main

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// redrawTerminal makes whatever runs in the sandbox's terminal (a shell, an
// agent's full-screen interface) redraw itself after Rig has printed over it.
// It shrinks the terminal by one row and restores it: the engine passes each
// resize on, and shells and terminal interfaces repaint on a resize. Without
// it, a notice printed mid-session leaves the prompt hidden and the session
// looks frozen until you press Ctrl-C.
func redrawTerminal() {
	fd := int(os.Stdin.Fd())
	ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	if err != nil || ws.Row < 2 {
		return
	}
	smaller := *ws
	smaller.Row--
	if unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &smaller) != nil {
		return
	}
	time.Sleep(150 * time.Millisecond)
	_ = unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, ws)
}

// setTitle shows text in the terminal window's title, where it stays visible
// even when an agent's interface repaints the screen.
func setTitle(text string) {
	if stderrTTY {
		os.Stderr.WriteString("\033]0;" + text + "\007")
	}
}

// pushTitle saves the terminal's window title and popTitle restores it, so
// alerts shown in the title during a session do not outlive it.
func pushTitle() {
	if stderrTTY {
		os.Stderr.WriteString("\033[22;0t")
	}
}

func popTitle() {
	if stderrTTY {
		os.Stderr.WriteString("\033[23;0t")
	}
}
