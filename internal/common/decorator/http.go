package decorator

import (
	"context"

	"github.com/sirupsen/logrus"
)

func ApplyHttpDecorators[H any, R any](handler HttpHandler[H, R], logger *logrus.Entry, metricsClient MetricsClient) HttpHandler[H, R] {
	return httpLoggingDecorator[H, R]{
		base: httpMetricsDecorator[H, R]{
			base:   handler,
			client: metricsClient,
		},
		logger: logger,
	}
}

type HttpHandler[Q any, R any] interface {
	Handle(ctx context.Context, cmd Q) (R, error)
}
