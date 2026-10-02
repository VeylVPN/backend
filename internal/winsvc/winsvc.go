package winsvc

import (
	"context"
	"sync"
)

var (
	baseOnce   sync.Once
	baseCtx    context.Context
	baseCancel context.CancelFunc
)

func base() (context.Context, context.CancelFunc) {
	baseOnce.Do(func() {
		baseCtx, baseCancel = context.WithCancel(context.Background())
	})
	return baseCtx, baseCancel
}

func Context() context.Context {
	ctx, _ := base()
	return ctx
}

func stop() {
	_, cancel := base()
	cancel()
}
