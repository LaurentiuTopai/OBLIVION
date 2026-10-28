package main

import (
	"context"
	"log"
	"os/signal"
	"os"
	"syscall"
	"time"
	"oblivion/internal/loader"
	"oblivion/internal/policy"
	"oblivion/internal/alert"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	
	w:= alert.NewWriter(os.Stdout)
	eng := policy.NewEngine(w.Write,
	policy.ExecFromTmp{},
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


	)


	if err := loader.Run(ctx,eng.Handle); err != nil {
		log.Fatalf("%+v", err)
	}
}
