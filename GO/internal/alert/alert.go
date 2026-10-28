package alert

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

type Alert struct {
	Rule     string    `json:"rule"`
	Severity int       `json:"severity"` // 1=info .. 5=critic
	Mitre    string    `json:"mitre"`
	Tgid     uint32    `json:"tgid"`
	Ppid     uint32    `json:"ppid"`
	Comm     string    `json:"comm"`
	Exe      string    `json:"exe"`
	Detail   string    `json:"detail"`
	Time     time.Time `json:"ts"`
}

type Writer struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func NewWriter(w io.Writer) *Writer {
	return &Writer{enc: json.NewEncoder(w)}
}

func (w *Writer) Write(a *Alert) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.enc.Encode(a)
}
