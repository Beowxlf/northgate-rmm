package sequence

type directoryLock interface {
	Close() error
}
