package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
)

type PrettyHandler struct {
	out   io.Writer
	level slog.Leveler
	mu    *sync.Mutex
	attrs []slog.Attr
	group string
}

func NewPrettyHandler(out io.Writer, level slog.Leveler) *PrettyHandler {
	return &PrettyHandler{
		out:   out,
		level: level,
		mu:    &sync.Mutex{},
	}
}

func (h *PrettyHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *PrettyHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder

	timeStr := r.Time.Format("15:04:05")
	levelStr := r.Level.String()

	source := "unknown"
	if r.PC != 0 {
		fs := runtime.CallersFrames([]uintptr{r.PC})
		frame, _ := fs.Next()

		source = fmt.Sprintf("%s:%d", filepath.Base(frame.File), frame.Line)
	}

	fmt.Fprintf(&b, "[%s][%s][%s] - %s", timeStr, levelStr, source, r.Message)

	for _, a := range h.attrs {
		writeAttr(&b, a)
	}

	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a)
		return true
	})

	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()

	_, err := h.out.Write([]byte(b.String()))
	return err
}

func (h *PrettyHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := *h
	next.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &next
}

func (h *PrettyHandler) WithGroup(name string) slog.Handler {
	next := *h
	next.group = name
	return &next
}

func writeAttr(b *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}

	a.Value = a.Value.Resolve()

	fmt.Fprintf(b, " %s=%v", a.Key, a.Value.Any())
}
