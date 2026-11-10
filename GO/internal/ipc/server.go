package ipc

import (
	"bufio"
	"encoding/json"
	"net"
	"oblivion/internal/alert"
	"os"
	"sync"
	"syscall"
)

const SocketPath = "/tmp/oblivion.sock"

type Command struct {
	Action string `json:"action"` // "kill" | "stop" | "cont"
	Tgid   uint32 `json:"tgid"`
}

type Server struct {
	mu      sync.Mutex
	clients map[net.Conn]struct{}
}

func NewServer() *Server {
	return &Server{clients: make(map[net.Conn]struct{})}
}

func (s *Server) Start() error {
	_ = os.Remove(SocketPath)
	l, err := net.Listen("unix", SocketPath)
	if err != nil {
		return err
	}
	// Permitem utilizatorului non-root (Wails UI) sa se conecteze la socket
	_ = os.Chmod(SocketPath, 0666)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				continue
			}
			s.mu.Lock()
			s.clients[conn] = struct{}{}
			s.mu.Unlock()

			go s.handleClient(conn)
		}
	}()
	return nil
}

func (s *Server) handleClient(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.clients, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var cmd Command
		if err := json.Unmarshal(scanner.Bytes(), &cmd); err != nil {
			continue
		}
		if cmd.Tgid <= 1 {
			continue
		}
		switch cmd.Action {
		case "kill":
			_ = syscall.Kill(int(cmd.Tgid), syscall.SIGKILL)
		case "stop":
			_ = syscall.Kill(int(cmd.Tgid), syscall.SIGSTOP)
		case "cont":
			_ = syscall.Kill(int(cmd.Tgid), syscall.SIGCONT)
		}
	}
}

// Broadcast trimite alerta serializata JSON Lines catre toate ferestrele UI conectate
func (s *Server) Broadcast(a *alert.Alert) {
	data, err := json.Marshal(a)
	if err != nil {
		return
	}
	data = append(data, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		if _, err := c.Write(data); err != nil {
			c.Close()
			delete(s.clients, c)
		}
	}
}
