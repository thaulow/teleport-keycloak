package tracing

import (
	"context"
	"os"
	"path"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"google.golang.org/grpc"
)

type Config struct {
	Service     string
	AgentAddr   string
	Directory   string
	Attributes  []attribute.KeyValue
	SampleRatio float64
}

// InitializeTraceProvider creates and configures the corresponding trace provider.
func InitializeTraceProvider(ctx context.Context, cfg Config) (func(ctx context.Context), error) {
	var traceExp sdktrace.SpanExporter
	clean := func() error { return nil }

	switch {
	case cfg.AgentAddr != "":
		traceClient := otlptracegrpc.NewClient(
			otlptracegrpc.WithInsecure(),
			otlptracegrpc.WithEndpoint(cfg.AgentAddr),
			otlptracegrpc.WithDialOption(grpc.WithBlock()),
		)
		exporter, err := otlptrace.New(ctx, traceClient)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		traceExp = exporter
	case cfg.Directory != "":
		f, err := os.OpenFile(path.Join(cfg.Directory, "tracing"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			return nil, trace.Wrap(err)
		}

		exporter, err := stdouttrace.New(stdouttrace.WithWriter(f))
		if err != nil {
			return nil, trace.Wrap(err)
		}

		clean = f.Close

		traceExp = exporter
	default:
		return nil, trace.BadParameter("invalid tracing configuration")
	}

	attrs := []attribute.KeyValue{
		// the service name used to display traces in backends
		semconv.ServiceNameKey.String(cfg.Service),
		attribute.String("teleport.version", teleport.Version),
	}
	attrs = append(attrs, cfg.Attributes...)

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithAttributes(attrs...),
	)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	bsp := sdktrace.NewBatchSpanProcessor(traceExp)
	tracerProvider := sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.TraceIDRatioBased(cfg.SampleRatio)),
		sdktrace.WithResource(res),
		sdktrace.WithSpanProcessor(bsp),
	)

	// set global propagator the default is no-op.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(propagation.TraceContext{}, propagation.Baggage{}))
	otel.SetTracerProvider(tracerProvider)

	return func(ctx context.Context) {
		if err := bsp.ForceFlush(ctx); err != nil {
			otel.Handle(err)
		}
		if err := traceExp.Shutdown(ctx); err != nil {
			otel.Handle(err)
		}

		if err := clean(); err != nil {
			otel.Handle(err)
		}
	}, nil
}
