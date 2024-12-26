package logs

import (
	"github.com/lcvvvv/logs"
)

type Level = logs.Level

const (
	LevelDebug Level = iota
	LevelWarn
	LevelInfo
	LevelError
)

type Logger interface {
	Debugf(format string, v ...interface{})
	Debug(v ...interface{})
	Warnf(format string, v ...interface{})
	Warn(v ...interface{})
	Errorf(format string, v ...interface{})
	Error(v ...interface{})
	Infof(format string, s ...interface{})
	Info(v ...interface{})
}

var (
	defaultLogs Logger = logs.NewLogger(logs.Info)
)

func SetLogger(log Logger) {
	defaultLogs = log
}

func SetLevel(level logs.Level) {
	defaultLogs.(*logs.Logger).SetLevel(level)
}

func Debugf(format string, v ...interface{}) {
	defaultLogs.Debugf(format, v...)
}

func Debug(v ...interface{}) {
	defaultLogs.Debug(v...)
}

func Errorf(format string, v ...interface{}) {
	defaultLogs.Errorf(format, v...)
}

func Error(v ...interface{}) {
	defaultLogs.Error(v...)
}

func Iofof(format string, v ...interface{}) {
	defaultLogs.Infof(format, v...)
}

func Info(v ...interface{}) {
	defaultLogs.Info(v...)
}

func Warnf(format string, v ...interface{}) {
	defaultLogs.Warnf(format, v...)
}

func Warn(v ...interface{}) {
	defaultLogs.Warn(v...)
}
