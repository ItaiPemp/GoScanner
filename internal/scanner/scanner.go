package scan

import "context"

type Scanner interface {
	InitWorkers(ctx context.Context)
	InitScan(ctx context.Context, target *Target) error
}
