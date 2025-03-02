package utils

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// LogLevel represents the severity level of a log entry
type LogLevel int

const (
	// DEBUG level for detailed troubleshooting information
	DEBUG LogLevel = iota
	// INFO level for general operational information
	INFO
	// WARN level for potentially harmful situations
	WARN
	// ERROR level for error events that might still allow continued operation
	ERROR
	// FATAL level for very severe error events that will lead to application termination
	FATAL
)

// String returns the string representation of a LogLevel
func (l LogLevel) String() string {
	switch l {
	case DEBUG:
		return "DEBUG"
	case INFO:
		return "INFO"
	case WARN:
		return "WARN"
	case ERROR:
		return "ERROR"
	case FATAL:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

// Logger is a simple logging utility
type Logger struct {
	level      LogLevel
	logger     *log.Logger
	fileWriter io.WriteCloser
}

// NewLogger creates a new logger
func NewLogger(level LogLevel, logDir string) (*Logger, error) {
	// Create multi-writer for console and file
	writers := []io.Writer{os.Stdout}

	var fileWriter io.WriteCloser
	if logDir != "" {
		// Create log directory if it doesn't exist
		if err := os.MkdirAll(logDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create log directory: %w", err)
		}

		// Create log file with current timestamp
		logFile := filepath.Join(logDir, fmt.Sprintf("dpos_%s.log", time.Now().Format("20060102_150405")))
		file, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open log file: %w", err)
		}
		fileWriter = file
		writers = append(writers, file)
	}

	multiWriter := io.MultiWriter(writers...)
	logger := log.New(multiWriter, "", log.LstdFlags)

	return &Logger{
		level:      level,
		logger:     logger,
		fileWriter: fileWriter,
	}, nil
}

// SetLevel sets the log level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a debug message
func (l *Logger) Debug(msg string, keyvals ...interface{}) {
	if l.level <= DEBUG {
		l.log(DEBUG, msg, keyvals...)
	}
}

// Info logs an informational message
func (l *Logger) Info(msg string, keyvals ...interface{}) {
	if l.level <= INFO {
		l.log(INFO, msg, keyvals...)
	}
}

// Warn logs a warning message
func (l *Logger) Warn(msg string, keyvals ...interface{}) {
	if l.level <= WARN {
		l.log(WARN, msg, keyvals...)
	}
}

// Error logs an error message
func (l *Logger) Error(msg string, keyvals ...interface{}) {
	if l.level <= ERROR {
		l.log(ERROR, msg, keyvals...)
	}
}

// Fatal logs a fatal message and exits the program
func (l *Logger) Fatal(msg string, keyvals ...interface{}) {
	if l.level <= FATAL {
		l.log(FATAL, msg, keyvals...)
	}
	os.Exit(1)
}

// log formats and logs a message with key-value pairs
func (l *Logger) log(level LogLevel, msg string, keyvals ...interface{}) {
	// Format key-value pairs
	kvStr := ""
	for i := 0; i < len(keyvals); i += 2 {
		key := keyvals[i]
		var val interface{} = "MISSING"
		if i+1 < len(keyvals) {
			val = keyvals[i+1]
		}
		kvStr += fmt.Sprintf(" %v=%v", key, val)
	}

	l.logger.Printf("[%s] %s%s", level.String(), msg, kvStr)
}

// Close closes the file writer if it exists
func (l *Logger) Close() error {
	if l.fileWriter != nil {
		return l.fileWriter.Close()
	}
	return nil
}
