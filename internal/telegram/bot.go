// Package telegram provides a Telegram bot for out-of-band control of ShellGate.
package telegram

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// ServerController is the interface through which the bot controls the server.
type ServerController interface {
	StartListener() (string, error)
	StopListener() error
	IsListening() bool
	GenerateOneTimeToken(ttl time.Duration) (string, error)
	RevokeToken(token string) error
	GetStatus() ServerStatus
	ListSessions() []SessionInfo
	KillSession(id string) error
	AddWhitelistIP(cidr string) error
	RemoveWhitelistIP(cidr string) error
	ToggleRecording() bool
	CreateShareLink(sessionID string) (string, error)
	GetPort() int
	SetPort(port int)
}

// ServerStatus mirrors server.ServerStatus.
type ServerStatus struct {
	Listening   bool
	Port        int
	Uptime      time.Duration
	Sessions    int
	TLSEnabled  bool
	RecordingOn bool
	BannedIPs   int
}

// SessionInfo mirrors server.SessionInfo.
type SessionInfo struct {
	ID        string
	ClientIP  string
	Duration  time.Duration
	UserAgent string
}

// StealthController is the interface for stealth mode operations.
type StealthController interface {
	Open(ttl time.Duration) (int, error)
	Close() error
	ActivePort() int
}

// ACLController is the interface for ACL operations from the bot.
type ACLController interface {
	Ban(ip string)
	Unban(ip string)
	ListBanned() map[string]time.Time
	ListNetworks() []string
}

// BotConfig holds configuration for the Telegram bot.
type BotConfig struct {
	Token        string
	AllowedUsers []int64
	ExternalHost string
	TLSEnabled   bool
	Stealth      bool
}

// Bot is the Telegram bot for controlling ShellGate.
type Bot struct {
	api          *tgbotapi.BotAPI
	cfg          BotConfig
	controller   ServerController
	stealth      StealthController
	acl          ACLController
	allowedUsers map[int64]bool
	chatIDs      map[int64]bool
	chatMu       sync.RWMutex

	// Rate limiting for /open command
	lastOpen   time.Time
	lastOpenMu sync.Mutex

	done chan struct{}
	wg   sync.WaitGroup
}

// NewBot creates a new Telegram bot.
func NewBot(cfg BotConfig, controller ServerController, stealth StealthController, aclCtrl ACLController) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(cfg.Token)
	if err != nil {
		return nil, fmt.Errorf("create telegram bot: %w", err)
	}

	allowed := make(map[int64]bool)
	for _, id := range cfg.AllowedUsers {
		allowed[id] = true
	}

	bot := &Bot{
		api:          api,
		cfg:          cfg,
		controller:   controller,
		stealth:      stealth,
		acl:          aclCtrl,
		allowedUsers: allowed,
		chatIDs:      make(map[int64]bool),
		done:         make(chan struct{}),
	}

	slog.Info("telegram bot initialized", "username", api.Self.UserName)
	return bot, nil
}

// Start begins polling for Telegram updates.
func (b *Bot) Start() {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 30

	updates := b.api.GetUpdatesChan(u)

	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		for {
			select {
			case <-b.done:
				return
			case update, ok := <-updates:
				if !ok {
					return
				}
				if update.Message == nil || !update.Message.IsCommand() {
					continue
				}
				b.handleUpdate(update)
			}
		}
	}()

	slog.Info("telegram bot started polling")
}

// Stop stops the bot polling and waits for the goroutine to exit.
func (b *Bot) Stop() {
	b.api.StopReceivingUpdates()
	close(b.done)
	b.wg.Wait()
}

// SendNotification sends a message to all registered chat IDs.
func (b *Bot) SendNotification(text string) {
	b.chatMu.RLock()
	defer b.chatMu.RUnlock()

	for chatID := range b.chatIDs {
		msg := tgbotapi.NewMessage(chatID, text)
		msg.ParseMode = "Markdown"
		if _, err := b.api.Send(msg); err != nil {
			slog.Error("telegram notification failed", "chat_id", chatID, "error", err)
		}
	}
}

// handleUpdate processes a single Telegram update.
func (b *Bot) handleUpdate(update tgbotapi.Update) {
	userID := update.Message.From.ID
	chatID := update.Message.Chat.ID

	// Authorization check — silently drop unauthorized messages
	if !b.allowedUsers[userID] {
		slog.Warn("telegram: unauthorized user", "user_id", userID, "username", update.Message.From.UserName)
		return
	}

	// Register chat for notifications
	b.chatMu.Lock()
	b.chatIDs[chatID] = true
	b.chatMu.Unlock()

	cmd := update.Message.Command()
	args := update.Message.CommandArguments()

	handler, ok := commandHandlers[cmd]
	if !ok {
		b.reply(chatID, "Unknown command. Use /help to see available commands.")
		return
	}

	handler(b, chatID, args)
}

// reply sends a text message to a chat.
func (b *Bot) reply(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	if _, err := b.api.Send(msg); err != nil {
		slog.Error("telegram reply failed", "chat_id", chatID, "error", err)
	}
}

// isRateLimited checks if the /open command is rate limited (1 per 10s).
func (b *Bot) isRateLimited() bool {
	b.lastOpenMu.Lock()
	defer b.lastOpenMu.Unlock()

	if time.Since(b.lastOpen) < 10*time.Second {
		return true
	}
	b.lastOpen = time.Now()
	return false
}

// buildURL constructs the access URL.
func (b *Bot) buildURL(port int, token string) string {
	scheme := "http"
	if b.cfg.TLSEnabled {
		scheme = "https"
	}

	host := b.cfg.ExternalHost
	if host == "" {
		host = "localhost"
	}

	return fmt.Sprintf("%s://%s:%d/?token=%s", scheme, host, port, token)
}
