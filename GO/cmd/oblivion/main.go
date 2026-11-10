package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"oblivion/internal/alert"
	"oblivion/internal/ipc"
	"oblivion/internal/loader"
	"oblivion/internal/policy"
	"oblivion/internal/policy/ruleset"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rulesDir := filepath.Join("internal", "policy", "rules")
	declarativeRules, err := ruleset.LoadRules(rulesDir)
	if err != nil {
		log.Fatalf("rules load: %v", err)
	}

	staticRules := []policy.Rule{
		policy.SelfDelete{},
		policy.MemoryExploit{},
		policy.Ransomware{
			RenameThreshold: 20,
			UnlinkThreshold: 20,
			CreateThreshold: 20,
			ExtThreshold:    10,
			DirThreshold:    10,
			Window:          5 * time.Second,
			ScoreWindow:     30 * time.Second,
			AlertScore:      5,
		},
	}

	allRules := make([]policy.Rule, 0, len(staticRules)+len(declarativeRules))
	allRules = append(allRules, staticRules...)
	for _, r := range declarativeRules {
		allRules = append(allRules, r)
	}

	ipcSrv := ipc.NewServer()
	if err := ipcSrv.Start(); err != nil {
		log.Fatalf("Eroare pornire IPC socket: %v", err)
	}

	w := alert.NewWriter(os.Stdout)
	eng := policy.NewEngine(func(a *alert.Alert) {
		w.Write(a)
		ipcSrv.Broadcast(a)
	}, allRules...)

	if err := loader.Run(ctx, eng.Handle); err != nil {
		log.Fatalf("%+v", err)
	}
}
