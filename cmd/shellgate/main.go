// ShellGate — Instant web-based terminal access to any server from a single binary.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cc1a2b/shellgate/internal/auth"
	"github.com/cc1a2b/shellgate/internal/server"
	sgTLS "github.com/cc1a2b/shellgate/internal/tls"
	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func main() {
	if err := rootCmd().Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func configDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".shellgate")
	}
	return filepath.Join(home, ".shellgate")
}

func rootCmd() *cobra.Command {
	var (
		host            string
		port            int
		shell           string
		verbose         bool
		authMode        string
		token           string
		password        string
		allowIP         string
		rateLimit       float64
		noAuthAck       bool
		tlsFlag         bool
		domain          string
		certFile        string
		keyFile         string
		maxSessions     int
		timeout         string
		idleTimeout     string
		record          bool
		recordDir       string
		share           bool
		shareTTL        string
		shareMaxViewers int
	)

	cmd := &cobra.Command{
		Use:   "shellgate",
		Short: "Instant web-based terminal access from a single binary",
		Long:  "ShellGate exposes a fully interactive terminal session over the browser via WebSocket.\nYour server is one click away.",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(serverParams{
				host: host, port: port, shell: shell, verbose: verbose,
				authMode: authMode, token: token, password: password,
				allowIP: allowIP, rateLimit: rateLimit, noAuthAck: noAuthAck,
				tls: tlsFlag, domain: domain, certFile: certFile, keyFile: keyFile,
				maxSessions: maxSessions, timeout: timeout, idleTimeout: idleTimeout,
				record: record, recordDir: recordDir,
				share: share, shareTTL: shareTTL, shareMaxViewers: shareMaxViewers,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	defaultShell := os.Getenv("SHELL")
	if defaultShell == "" {
		defaultShell = "/bin/bash"
	}

	f := cmd.Flags()

	// Server
	f.StringVar(&host, "host", "0.0.0.0", "Host address to bind to")
	f.IntVar(&port, "port", 8080, "Port to listen on")
	f.StringVar(&shell, "shell", defaultShell, "Shell to spawn")
	f.BoolVar(&verbose, "verbose", false, "Enable verbose (debug) logging")

	// Auth
	f.StringVar(&authMode, "auth", "token", "Auth mode: none|token|password|otp")
	f.StringVar(&token, "token", os.Getenv("SHELLGATE_TOKEN"), "Static auth token")
	f.StringVar(&password, "password", "", "Password for web login")
	f.StringVar(&allowIP, "allow-ip", "", "Comma-separated CIDR whitelist")
	f.Float64Var(&rateLimit, "rate-limit", 10, "Requests per second per IP (0=disable)")
	f.BoolVar(&noAuthAck, "i-know-what-im-doing", false, "Acknowledge running without auth")

	// TLS
	f.BoolVar(&tlsFlag, "tls", false, "Enable TLS")
	f.StringVar(&domain, "domain", "", "Domain for Let's Encrypt auto-TLS")
	f.StringVar(&certFile, "cert", "", "Path to custom TLS certificate")
	f.StringVar(&keyFile, "key", "", "Path to custom TLS key")

	// Sessions
	f.IntVar(&maxSessions, "max-sessions", 5, "Maximum concurrent sessions")
	f.StringVar(&timeout, "timeout", "30m", "Session timeout (0=no timeout)")
	f.StringVar(&idleTimeout, "idle-timeout", "10m", "Idle timeout (0=no timeout)")

	// Recording
	f.BoolVar(&record, "record", false, "Enable session recording (asciicast v2)")
	f.StringVar(&recordDir, "record-dir", "", "Recording output directory")

	// Sharing
	f.BoolVar(&share, "share", false, "Enable session sharing")
	f.StringVar(&shareTTL, "share-ttl", "1h", "Share link TTL")
	f.IntVar(&shareMaxViewers, "share-max-viewers", 10, "Max viewers per share")

	// Subcommands
	cmd.AddCommand(serveCmd(cmd))
	cmd.AddCommand(versionCmd())
	cmd.AddCommand(setupOTPCmd())
	cmd.AddCommand(sessionsCmd())
	cmd.AddCommand(completionCmd())

	return cmd
}

// serveCmd is an explicit alias for the root command.
func serveCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the ShellGate server (same as running without subcommand)",
		RunE:  root.RunE,
	}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("shellgate %s\n  commit: %s\n  built:  %s\n", version, commit, date)
		},
	}
}

func setupOTPCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "setup-otp",
		Short: "Configure TOTP two-factor authentication",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := configDir()
			hostname, _ := os.Hostname()
			if hostname == "" {
				hostname = "server"
			}

			key, err := auth.SetupOTP(dir, "shellgate@"+hostname)
			if err != nil {
				return err
			}

			fmt.Println("TOTP setup complete!")
			fmt.Printf("  Secret: %s\n", key.Secret())
			fmt.Printf("  URI:    %s\n", key.URL())
			fmt.Println("\nAdd this to your authenticator app.")
			fmt.Printf("Secret stored in: %s\n", filepath.Join(dir, "otp.key"))

			return nil
		},
	}
}

func sessionsCmd() *cobra.Command {
	var host string
	var port int
	var token string

	cmd := &cobra.Command{
		Use:   "sessions",
		Short: "List active sessions on a running ShellGate instance",
		RunE: func(cmd *cobra.Command, args []string) error {
			url := fmt.Sprintf("http://%s:%d/api/sessions", host, port)

			req, err := http.NewRequest(http.MethodGet, url, nil)
			if err != nil {
				return fmt.Errorf("create request: %w", err)
			}

			if token != "" {
				req.Header.Set("Authorization", "Bearer "+token)
			}

			client := &http.Client{Timeout: 5 * time.Second}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("connect to ShellGate: %w", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("server returned %d", resp.StatusCode)
			}

			var sessions []map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
				return fmt.Errorf("decode response: %w", err)
			}

			if len(sessions) == 0 {
				fmt.Println("No active sessions.")
				return nil
			}

			fmt.Printf("%-18s %-22s %-20s %s\n", "ID", "CLIENT", "DURATION", "USER-AGENT")
			for _, s := range sessions {
				id, _ := s["id"].(string)
				ip, _ := s["client_ip"].(string)
				dur, _ := s["duration"].(string)
				ua, _ := s["user_agent"].(string)
				if len(ua) > 30 {
					ua = ua[:27] + "..."
				}
				if len(id) > 16 {
					id = id[:16]
				}
				fmt.Printf("%-18s %-22s %-20s %s\n", id, ip, dur, ua)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&host, "host", "127.0.0.1", "ShellGate host")
	cmd.Flags().IntVar(&port, "port", 8080, "ShellGate port")
	cmd.Flags().StringVar(&token, "token", os.Getenv("SHELLGATE_TOKEN"), "Auth token")

	return cmd
}

func completionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "completion [bash|zsh|fish|powershell]",
		Short: "Generate shell completion scripts",
		Long: `Generate shell completion scripts for ShellGate.

  # Bash
  shellgate completion bash > /etc/bash_completion.d/shellgate

  # Zsh
  shellgate completion zsh > "${fpath[1]}/_shellgate"

  # Fish
  shellgate completion fish > ~/.config/fish/completions/shellgate.fish`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"bash", "zsh", "fish", "powershell"},
		RunE: func(cmd *cobra.Command, args []string) error {
			switch args[0] {
			case "bash":
				return cmd.Root().GenBashCompletion(os.Stdout)
			case "zsh":
				return cmd.Root().GenZshCompletion(os.Stdout)
			case "fish":
				return cmd.Root().GenFishCompletion(os.Stdout, true)
			case "powershell":
				return cmd.Root().GenPowerShellCompletionWithDesc(os.Stdout)
			default:
				return fmt.Errorf("unsupported shell: %s", args[0])
			}
		},
	}
}

type serverParams struct {
	host, shell, authMode, token, password, allowIP                   string
	domain, certFile, keyFile, timeout, idleTimeout, recordDir        string
	shareTTL                                                          string
	port, maxSessions, shareMaxViewers                                int
	rateLimit                                                         float64
	verbose, noAuthAck, tls, record, share                            bool
}

func runServer(p serverParams) error {
	logLevel := slog.LevelInfo
	if p.verbose {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel})))

	timeout, err := time.ParseDuration(p.timeout)
	if err != nil {
		return fmt.Errorf("parse timeout: %w", err)
	}
	idleTimeout, err := time.ParseDuration(p.idleTimeout)
	if err != nil {
		return fmt.Errorf("parse idle-timeout: %w", err)
	}

	recordDir := p.recordDir
	if recordDir == "" {
		recordDir = filepath.Join(configDir(), "recordings")
	}

	var shareTTL time.Duration
	if p.share {
		shareTTL, err = time.ParseDuration(p.shareTTL)
		if err != nil {
			return fmt.Errorf("parse share-ttl: %w", err)
		}
	}

	cfg := server.Config{
		Host: p.host, Port: p.port, Shell: p.shell, Verbose: p.verbose,
		AuthMode: p.authMode, Token: p.token, Password: p.password,
		OTPDir: configDir(), AllowIP: p.allowIP, RateLimit: p.rateLimit,
		NoAuthAck:   p.noAuthAck,
		MaxSessions: p.maxSessions, Timeout: timeout, IdleTimeout: idleTimeout,
		RecordEnabled: p.record, RecordDir: recordDir,
		ShareEnabled: p.share, ShareTTL: shareTTL, ShareMaxViewers: p.shareMaxViewers,
	}

	// Setup TLS
	tlsInfo := "disabled"
	if p.tls {
		cfg.TLSEnabled = true
		certDir := filepath.Join(configDir(), "certs")

		if p.certFile != "" && p.keyFile != "" {
			tlsCfg, err := sgTLS.LoadCertificate(p.certFile, p.keyFile)
			if err != nil {
				return fmt.Errorf("load TLS certificate: %w", err)
			}
			cfg.TLSConfig = tlsCfg
			tlsInfo = "custom certificate"
		} else if p.domain != "" {
			tlsCfg, manager, err := sgTLS.NewAutoTLS(sgTLS.AutoTLSConfig{
				Domain: p.domain, CacheDir: certDir,
			})
			if err != nil {
				return fmt.Errorf("setup auto TLS: %w", err)
			}
			cfg.TLSConfig = tlsCfg
			cfg.AutoCert = manager
			tlsInfo = fmt.Sprintf("Let's Encrypt (%s)", p.domain)
			if p.port == 8080 {
				p.port = 443
				cfg.Port = 443
			}
		} else {
			tlsCfg, fingerprint, err := sgTLS.GenerateSelfSigned(sgTLS.SelfSignedConfig{
				CertDir: certDir, Hosts: []string{p.host, "localhost", "127.0.0.1"},
			})
			if err != nil {
				return fmt.Errorf("generate self-signed cert: %w", err)
			}
			cfg.TLSConfig = tlsCfg
			tlsInfo = "self-signed"
			fmt.Fprintf(os.Stderr, "Certificate SHA-256: %s\n", fingerprint)
		}
	}

	srv, err := server.New(cfg)
	if err != nil {
		return fmt.Errorf("create server: %w", err)
	}

	printBanner(p, srv, tlsInfo)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)

	// HTTP→HTTPS redirect for autocert
	if srv.AutoCertManager() != nil {
		go func() {
			httpSrv := &http.Server{
				Addr:              ":80",
				Handler:           srv.AutoCertManager().HTTPHandler(nil),
				ReadHeaderTimeout: 10 * time.Second,
			}
			slog.Info("HTTP→HTTPS redirect on :80")
			if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("HTTP redirect error", "error", err)
			}
		}()
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err.Error() != "http: Server closed" {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("server: %w", err)
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "\nShutting down...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown: %w", err)
		}
		fmt.Fprintln(os.Stderr, "Done.")
	}

	return nil
}

func printBanner(p serverParams, srv *server.Server, tlsInfo string) {
	displayHost := p.host
	if p.host == "0.0.0.0" {
		displayHost = "localhost"
	}

	scheme := "http"
	if p.tls {
		scheme = "https"
	}

	authInfo := srv.Auth().Name()
	extra := ""

	if ta, ok := srv.Auth().(*auth.TokenAuth); ok {
		t := ta.Token()
		if len(t) > 12 {
			extra += fmt.Sprintf("\n│  Token: %s...%s", t[:6], t[len(t)-6:])
		} else {
			extra += fmt.Sprintf("\n│  Token: %s", t)
		}
	}

	if p.tls {
		extra += fmt.Sprintf("\n│  TLS: %s", tlsInfo)
	}

	if p.record {
		extra += "\n│  Recording: enabled"
	}

	if p.share {
		extra += "\n│  Sharing: enabled"
	}

	fmt.Fprintf(os.Stderr, `
┌─────────────────────────────────────────┐
│  ShellGate %s
│  > %s://%s:%d
│  > Shell: %s
│  > Auth: %s%s
└─────────────────────────────────────────┘
`, version, scheme, displayHost, p.port, p.shell, authInfo, extra)
}
