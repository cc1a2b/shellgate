package session

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// asciicast v2 format: https://docs.asciinema.org/manual/asciicast/v2/

// asciicastHeader is the first line of an asciicast v2 file.
type asciicastHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env,omitempty"`
	Title     string            `json:"title,omitempty"`
}

// Recorder records terminal I/O in asciicast v2 format.
type Recorder struct {
	file     *os.File
	start    time.Time
	mu       sync.Mutex
	buf      []byte
	bufLimit int
	closed   bool
}

// RecorderConfig holds configuration for session recording.
type RecorderConfig struct {
	Dir       string
	SessionID string
	Width     int
	Height    int
	Shell     string
	Title     string
}

// NewRecorder creates a new session recorder that writes asciicast v2 files.
func NewRecorder(cfg RecorderConfig) (*Recorder, error) {
	if err := os.MkdirAll(cfg.Dir, 0700); err != nil {
		return nil, fmt.Errorf("create recording dir: %w", err)
	}

	filename := fmt.Sprintf("session-%s-%s.cast",
		cfg.SessionID,
		time.Now().Format("20060102-150405"))
	path := filepath.Join(cfg.Dir, filename)

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create recording file: %w", err)
	}

	// Write header
	header := asciicastHeader{
		Version:   2,
		Width:     cfg.Width,
		Height:    cfg.Height,
		Timestamp: time.Now().Unix(),
		Title:     cfg.Title,
		Env: map[string]string{
			"SHELL": cfg.Shell,
			"TERM":  "xterm-256color",
		},
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("marshal header: %w", err)
	}

	if _, err := f.Write(append(headerJSON, '\n')); err != nil {
		f.Close()
		return nil, fmt.Errorf("write header: %w", err)
	}

	return &Recorder{
		file:     f,
		start:    time.Now(),
		bufLimit: 4096,
	}, nil
}

// WriteOutput records terminal output data.
func (r *Recorder) WriteOutput(data []byte) error {
	return r.writeEvent("o", data)
}

// WriteInput records terminal input data.
func (r *Recorder) WriteInput(data []byte) error {
	return r.writeEvent("i", data)
}

// WriteResize records a terminal resize event.
func (r *Recorder) WriteResize(cols, rows int) error {
	resizeData := fmt.Sprintf(`"%dx%d"`, cols, rows)
	return r.writeRawEvent("r", []byte(resizeData))
}

// writeEvent records an event with the given type and data.
func (r *Recorder) writeEvent(eventType string, data []byte) error {
	escaped, err := json.Marshal(string(data))
	if err != nil {
		return fmt.Errorf("marshal event data: %w", err)
	}
	return r.writeRawEvent(eventType, escaped)
}

// writeRawEvent writes a raw asciicast v2 event line.
func (r *Recorder) writeRawEvent(eventType string, rawData []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}

	elapsed := time.Since(r.start).Seconds()
	line := fmt.Sprintf("[%.6f, %q, %s]\n", elapsed, eventType, rawData)

	r.buf = append(r.buf, line...)

	// Flush if buffer exceeds limit
	if len(r.buf) >= r.bufLimit {
		return r.flushLocked()
	}

	return nil
}

// Flush writes any buffered data to disk.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked()
}

func (r *Recorder) flushLocked() error {
	if len(r.buf) == 0 {
		return nil
	}

	_, err := r.file.Write(r.buf)
	r.buf = r.buf[:0]
	return err
}

// Close flushes and closes the recorder.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.closed {
		return nil
	}
	r.closed = true

	if err := r.flushLocked(); err != nil {
		r.file.Close()
		return err
	}
	return r.file.Close()
}

// FilePath returns the path to the recording file.
func (r *Recorder) FilePath() string {
	return r.file.Name()
}
