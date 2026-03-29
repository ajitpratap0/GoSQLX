module github.com/ajitpratap0/GoSQLX/integrations/opentelemetry

go 1.26.1

require (
	github.com/ajitpratap0/GoSQLX v1.13.0
	go.opentelemetry.io/otel v1.26.0
	go.opentelemetry.io/otel/sdk v1.26.0
	go.opentelemetry.io/otel/trace v1.26.0
)

require (
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	go.opentelemetry.io/otel/metric v1.26.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/ajitpratap0/GoSQLX => ../../
