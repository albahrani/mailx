package main

import (
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/albahrani/mailx/server/app"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetPrefix("mailx-server ")

	configFile := "config.json"
	if len(os.Args) > 1 {
		configFile = os.Args[1]
	}

	configData, err := os.ReadFile(configFile)
	if err != nil {
		log.Fatalf("Failed to read config file: %v", err)
	}

	var cfg app.Config
	if err := json.Unmarshal(configData, &cfg); err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	// Defaults.
	if cfg.GRPCPort == "" {
		cfg.GRPCPort = "8443"
	}
	if cfg.HTTPPort == "" {
		cfg.HTTPPort = "8080"
	}
	if cfg.MaxMessageSize == 0 {
		cfg.MaxMessageSize = 26214400 // 25 MB
	}
	if cfg.DefaultQuota == 0 {
		cfg.DefaultQuota = 10737418240 // 10 GB
	}

	srv, err := app.NewServer(&cfg)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}
	defer func() { _ = srv.Close() }()

	// HTTP well-known endpoint.
	http.HandleFunc("/.well-known/mailx-server", srv.WellKnownHandler)
	go func() {
		log.Printf("Starting HTTP server on :%s", cfg.HTTPPort)
		if err := http.ListenAndServe(":"+cfg.HTTPPort, nil); err != nil {
			log.Printf("HTTP server error: %v", err)
		}
	}()

	// gRPC server.
	var opts []grpc.ServerOption
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(cfg.TLSCertFile, cfg.TLSKeyFile)
		if err != nil {
			log.Fatalf("failed to load TLS credentials: %v", err)
		}
		opts = append(opts, grpc.Creds(creds))
		log.Println("TLS enabled for gRPC server")
	} else {
		log.Println("WARNING: Running gRPC server without TLS (insecure)")
	}

	gs := grpc.NewServer(opts...)
	srv.RegisterGRPC(gs)

	lis, err := net.Listen("tcp", ":"+cfg.GRPCPort)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	log.Printf("Starting gRPC server on :%s", cfg.GRPCPort)
	log.Printf("Domain: %s", cfg.Domain)
	log.Printf("Server signing public key: %x", srv.SigningPublicKey())

	// Graceful shutdown.
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Println("Shutting down server...")
		gs.GracefulStop()
		_ = srv.Close()
	}()

	if err := gs.Serve(lis); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
