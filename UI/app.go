
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"net"
	"sync"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

const SocketPath = "/tmp/oblivion.sock"

type AlertDTO struct {
	Rule     string    `json:"rule"`
	Severity int       `json:"severity"`
	Mitre    string    `json:"mitre"`
	Tgid     uint32    `json:"tgid"`
	Ppid     uint32    `json:"ppid"`
	Comm     string    `json:"comm"`
	Exe      string    `json:"exe"`
	Detail   string    `json:"detail"`
	Ts       time.Time `json:"ts"`
}

type App struct {
	ctx       context.Context
	mu        sync.Mutex
	conn      net.Conn
	batch     []AlertDTO
	connected bool
}

func NewApp() *App {
	return &App{
		batch: make([]AlertDTO, 0, 128),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	go a.socketReaderLoop()
	go a.uiFlushLoop()
}

func (a *App) socketReaderLoop() {
	for {
		conn, err := net.Dial("unix", SocketPath)
		if err != nil {
			a.setConnected(false)
			time.Sleep(1 * time.Second)
			continue
		}

		a.mu.Lock()
		a.conn = conn
		a.mu.Unlock()
		a.setConnected(true)

		scanner := bufio.NewScanner(conn)
		// Buffer marit la 1MB pentru linii JSON lungi
		buf := make([]byte, 0, 64*1024)
		scanner.Buffer(buf, 1024*1024)

		for scanner.Scan() {
			var al AlertDTO
			if err := json.Unmarshal(scanner.Bytes(), &al); err == nil {
				a.mu.Lock()
				a.batch = append(a.batch, al)
				a.mu.Unlock()
			}
		}
		conn.Close()
		a.setConnected(false)
	}
}

func (a *App) setConnected(status bool) {
	a.mu.Lock()
	a.connected = status
	a.mu.Unlock()
	if a.ctx != nil {
		runtime.EventsEmit(a.ctx, "daemon:status", status)
	}
}

func (a *App) GetDaemonStatus() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.connected
}

func (a *App) uiFlushLoop() {
	ticker := time.NewTicker(150 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		if a.ctx == nil {
			continue
		}
		a.mu.Lock()
		if len(a.batch) == 0 {
			a.mu.Unlock()
			continue
		}
		out := a.batch
		a.batch = make([]AlertDTO, 0, 128)
		a.mu.Unlock()

		runtime.EventsEmit(a.ctx, "alerts:batch", out)
	}
}

func (a *App) SendAction(action string, tgid uint32) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.conn == nil {
		return nil
	}
	payload, _ := json.Marshal(map[string]any{
		"action": action,
		"tgid":   tgid,
	})
	_, err := a.conn.Write(append(payload, '\n'))
	return err
}
