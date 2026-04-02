package logger

import (
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// Level represents log severity.
type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

var (
	currentLevel = LevelInfo
	out          = log.New(os.Stdout, "", log.LstdFlags)
)

// SetLevel sets the minimum log level.
func SetLevel(level string) {
	switch strings.ToLower(level) {
	case "debug":
		currentLevel = LevelDebug
	case "warn":
		currentLevel = LevelWarn
	case "error":
		currentLevel = LevelError
	default:
		currentLevel = LevelInfo
	}
}

// SetOutput sets the log output writer.
func SetOutput(w io.Writer) {
	out = log.New(w, "", log.LstdFlags)
}

// Debug logs a debug message with optional key-value pairs.
func Debug(msg string, kvs ...interface{}) {
	if currentLevel <= LevelDebug {
		out.Println("[DEBUG] " + formatMsg(msg, kvs...))
	}
}

// Info logs an info message with optional key-value pairs.
func Info(msg string, kvs ...interface{}) {
	if currentLevel <= LevelInfo {
		out.Println("[INFO] " + formatMsg(msg, kvs...))
	}
}

// Warn logs a warning message with optional key-value pairs.
func Warn(msg string, kvs ...interface{}) {
	if currentLevel <= LevelWarn {
		out.Println("[WARN] " + formatMsg(msg, kvs...))
	}
}

// Error logs an error message with optional key-value pairs.
func Error(msg string, kvs ...interface{}) {
	out.Println("[ERROR] " + formatMsg(msg, kvs...))
}

func formatMsg(msg string, kvs ...interface{}) string {
	if len(kvs) == 0 {
		return msg
	}

	var sb strings.Builder
	sb.WriteString(msg)
	for i := 0; i+1 < len(kvs); i += 2 {
		sb.WriteString(fmt.Sprintf(" %v=%v", kvs[i], kvs[i+1]))
	}
	// Handle odd number of args
	if len(kvs)%2 != 0 {
		sb.WriteString(fmt.Sprintf(" %v", kvs[len(kvs)-1]))
	}
	return sb.String()
}
