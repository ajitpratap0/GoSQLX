module github.com/ajitpratap0/GoSQLX/benchmarks/compare

go 1.26.9

require (
	github.com/ajitpratap0/GoSQLX v0.0.0-00010101000000-000000000000
	github.com/pganalyze/pg_query_go/v6 v6.2.5
	github.com/pingcap/tidb/pkg/parser v0.0.0-20261015143638-7193401b6746
	github.com/xwb1989/sqlparser v0.0.0-20180606152119-120387863bf2
	vitess.io/vitess v0.24.5
)

require (
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/golang/glog v1.2.5 // indirect
	github.com/lmittmann/tint v1.1.3 // indirect
	github.com/mattn/go-isatty v0.0.21 // indirect
	github.com/pingcap/errors v0.11.5-0.20250523034308-74f78ae071ee // indirect
	github.com/pingcap/failpoint v0.0.0-20240528011301-b51a646c7c86 // indirect
	github.com/pingcap/log v1.1.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20250313105119-ba97887b0a25 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.1 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.2 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/ajitpratap0/GoSQLX => ../..
