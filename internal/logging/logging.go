package logging

import (
	"log"
	"os"
)

type Logger struct {
	*log.Logger
}

func New(prefix string, debug bool) *Logger {
	flags := log.LstdFlags
	if debug {
		flags = log.LstdFlags | log.Lshortfile
	}
	return &Logger{Logger: log.New(os.Stdout, prefix, flags)}
}
