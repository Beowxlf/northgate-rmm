package spool

type directoryLock interface {
	Close() error
}
