package app

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type LogEntry struct {
	Seq    int64  `json:"seq"`
	Time   int64  `json:"time"`
	Source string `json:"source"` // app|engine|agent|<connection id>
	Level  string `json:"level"`
	Line   string `json:"line"`
}

// Logger keeps a ring buffer for the UI and appends to a rotating file.
type Logger struct {
	mu   sync.Mutex
	buf  []LogEntry
	seq  int64
	file *os.File
	path string
	size int64
	subs map[chan LogEntry]struct{}
}

const logRing = 3000
const logMaxFile = 10 << 20

func NewLogger(dir string) *Logger {
	os.MkdirAll(dir, 0o700)
	l := &Logger{path: filepath.Join(dir, "vpner.log"), subs: map[chan LogEntry]struct{}{}}
	l.open()
	return l
}

func (l *Logger) open() {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	st, _ := f.Stat()
	l.file = f
	if st != nil {
		l.size = st.Size()
	}
}

func (l *Logger) Add(source, level, line string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := LogEntry{Seq: l.seq, Time: time.Now().UnixMilli(), Source: source, Level: level, Line: line}
	l.buf = append(l.buf, e)
	if len(l.buf) > logRing {
		l.buf = l.buf[len(l.buf)-logRing:]
	}
	if l.file != nil {
		n, _ := fmt.Fprintf(l.file, "%s [%s] %s: %s\n", time.Now().Format("2006-01-02 15:04:05.000"), level, source, line)
		l.size += int64(n)
		if l.size > logMaxFile {
			l.file.Close()
			os.Rename(l.path, l.path+".1")
			l.open()
			l.size = 0
		}
	}
	for ch := range l.subs {
		select {
		case ch <- e:
		default:
		}
	}
}

func (l *Logger) Infof(source, f string, a ...any)  { l.Add(source, "info", fmt.Sprintf(f, a...)) }
func (l *Logger) Warnf(source, f string, a ...any)  { l.Add(source, "warning", fmt.Sprintf(f, a...)) }
func (l *Logger) Errorf(source, f string, a ...any) { l.Add(source, "error", fmt.Sprintf(f, a...)) }

func (l *Logger) Since(seq int64) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []LogEntry
	for _, e := range l.buf {
		if e.Seq > seq {
			out = append(out, e)
		}
	}
	return out
}

func (l *Logger) Subscribe() (chan LogEntry, func()) {
	ch := make(chan LogEntry, 512)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	return ch, func() {
		l.mu.Lock()
		delete(l.subs, ch)
		l.mu.Unlock()
	}
}

func (l *Logger) Writer(source string) io.Writer { return logWriter{l, source} }

type logWriter struct {
	l   *Logger
	src string
}

func (w logWriter) Write(p []byte) (int, error) {
	w.l.Add(w.src, "info", string(p))
	return len(p), nil
}
