package vmnet

import (
	"golang.org/x/exp/slog"
)

type nopHandler struct{}

var _ slog.Handler = (*nopHandler)(nil)

func (*nopHandler) Enabled(l slog.Level) bool               { return false }
func (h *nopHandler) Handle(r slog.Record) error            { return nil }
func (h *nopHandler) WithAttrs(as []slog.Attr) slog.Handler { return h }
func (h *nopHandler) WithGroup(name string) slog.Handler    { return h }

func errAttr(err error) slog.Attr {
	return slog.Any(slog.ErrorKey, err)
}
