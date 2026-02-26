package server

import (
	"crypto/rand"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"time"
)

// StealthConfig configures the stealth controller.
type StealthConfig struct {
	RandomPort   bool
	PortRangeMin int
	PortRangeMax int
	AutoCloseTTL time.Duration
}

// StealthController manages dynamic port selection and auto-close timers.
type StealthController struct {
	server     *Server
	cfg        StealthConfig
	closeTimer *time.Timer
	mu         sync.Mutex
	activePort int
}

// NewStealthController creates a new stealth controller for the given server.
func NewStealthController(srv *Server, cfg StealthConfig) *StealthController {
	if cfg.PortRangeMin <= 0 {
		cfg.PortRangeMin = 10000
	}
	if cfg.PortRangeMax <= 0 {
		cfg.PortRangeMax = 65000
	}
	if cfg.PortRangeMax <= cfg.PortRangeMin {
		cfg.PortRangeMax = cfg.PortRangeMin + 1000
	}

	return &StealthController{
		server: srv,
		cfg:    cfg,
	}
}

// Open starts the listener, optionally on a random port, with an auto-close timer.
// ttl overrides the default auto-close TTL if > 0.
func (sc *StealthController) Open(ttl time.Duration) (int, error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.server.IsListening() {
		return sc.activePort, nil
	}

	// Select port
	port := sc.server.GetPort()
	if sc.cfg.RandomPort {
		var err error
		port, err = sc.randomAvailablePort()
		if err != nil {
			return 0, fmt.Errorf("find available port: %w", err)
		}
		sc.server.SetPort(port)
	}

	addr, err := sc.server.StartListener()
	if err != nil {
		return 0, err
	}

	sc.activePort = port
	slog.Info("stealth: server opened", "addr", addr, "port", port)

	// Setup auto-close timer
	closeTTL := sc.cfg.AutoCloseTTL
	if ttl > 0 {
		closeTTL = ttl
	}
	if closeTTL > 0 {
		if sc.closeTimer != nil {
			sc.closeTimer.Stop()
		}
		sc.closeTimer = time.AfterFunc(closeTTL, func() {
			slog.Info("stealth: auto-closing after TTL", "ttl", closeTTL)
			if err := sc.Close(); err != nil {
				slog.Error("stealth: auto-close error", "error", err)
			}
		})
	}

	return port, nil
}

// Close stops the listener and cancels any auto-close timer.
func (sc *StealthController) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()

	if sc.closeTimer != nil {
		sc.closeTimer.Stop()
		sc.closeTimer = nil
	}

	err := sc.server.StopListener()
	sc.activePort = 0
	slog.Info("stealth: server closed")
	return err
}

// ActivePort returns the port the server is currently listening on, or 0 if not listening.
func (sc *StealthController) ActivePort() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if !sc.server.IsListening() {
		return 0
	}
	return sc.activePort
}

// randomAvailablePort picks a random port in the configured range and checks availability.
func (sc *StealthController) randomAvailablePort() (int, error) {
	portRange := sc.cfg.PortRangeMax - sc.cfg.PortRangeMin
	for attempts := 0; attempts < 50; attempts++ {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(portRange)))
		if err != nil {
			return 0, fmt.Errorf("random number: %w", err)
		}
		port := sc.cfg.PortRangeMin + int(n.Int64())

		// Check if port is available
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
		if err != nil {
			continue
		}
		ln.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no available port found in range %d-%d after 50 attempts", sc.cfg.PortRangeMin, sc.cfg.PortRangeMax)
}
