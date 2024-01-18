package vmnet

import (
	"context"
	"log/slog"
)

type nopHandler struct{}

var _ slog.Handler = (*nopHandler)(nil)

func (*nopHandler) Enabled(ctx context.Context, l slog.Level) bool    { return false }
func (h *nopHandler) Handle(ctx context.Context, r slog.Record) error { return nil }
func (h *nopHandler) WithAttrs(as []slog.Attr) slog.Handler           { return h }
func (h *nopHandler) WithGroup(name string) slog.Handler              { return h }
