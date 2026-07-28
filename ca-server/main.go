// Copyright 2026 INNO LOTUS PTY LTD
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"nip-ca-server/api"
	"nip-ca-server/ca"
	"nip-ca-server/db"
)

func main() {
	caNID := mustEnv("NIP_CA_NID")
	passphrase := mustEnv("NIP_CA_PASSPHRASE")
	baseURL := mustEnv("NIP_CA_BASE_URL")

	keyFile := envStr("NIP_CA_KEY_FILE", "/data/ca.key.enc")
	dbPath := envStr("NIP_CA_DB_PATH", "/data/ca.db")
	displayName := envStr("NIP_CA_DISPLAY_NAME", "NPS CA")
	agentDays := envInt("NIP_CA_AGENT_VALIDITY_DAYS", 30)
	nodeDays := envInt("NIP_CA_NODE_VALIDITY_DAYS", 90)
	renewalDays := envInt("NIP_CA_RENEWAL_WINDOW_DAYS", 7)
	port := envStr("PORT", "17440")

	sk := loadOrGenKey(keyFile, passphrase)

	store, err := db.Open(dbPath)
	if err != nil {
		slog.Error("failed to open database", "err", err)
		os.Exit(1)
	}

	state := &api.State{
		SK:          sk,
		PubKeyStr:   ca.PubKeyString(sk.Public().(ed25519.PublicKey)),
		DB:          store,
		CaNID:       caNID,
		BaseURL:     baseURL,
		DisplayName: displayName,
		AgentDays:   agentDays,
		NodeDays:    nodeDays,
		RenewalDays: renewalDays,
	}

	srv := &http.Server{
		Addr:         ":" + port,
		Handler:      api.Router(state),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("NIP CA Server starting", "port", port, "ca_nid", caNID)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "err", err)
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}

func loadOrGenKey(keyFile, passphrase string) ed25519.PrivateKey {
	if _, err := os.Stat(keyFile); err == nil {
		k, err := ca.LoadKey(keyFile, passphrase)
		if err != nil {
			slog.Error("failed to load key", "err", err)
			os.Exit(1)
		}
		return k
	}
	k, err := ca.GenerateKey()
	if err != nil {
		slog.Error("failed to generate key", "err", err)
		os.Exit(1)
	}
	if err := ca.SaveKey(k, keyFile, passphrase); err != nil {
		slog.Error("failed to save key", "err", err)
		os.Exit(1)
	}
	slog.Info("generated new CA key", "file", keyFile)
	return k
}

func mustEnv(k string) string {
	v := os.Getenv(k)
	if v == "" {
		slog.Error("required environment variable not set", "var", k)
		os.Exit(1)
	}
	return v
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
