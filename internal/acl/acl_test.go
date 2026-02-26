package acl

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDynamicACL_AddRemoveNetwork(t *testing.T) {
	acl, err := NewDynamicACL(Config{})
	require.NoError(t, err)
	defer acl.Close()

	// Add a network
	require.NoError(t, acl.AddNetwork("10.0.0.0/24"))
	networks := acl.ListNetworks()
	assert.Len(t, networks, 1)
	assert.Equal(t, "10.0.0.0/24", networks[0])

	// Add bare IP (should auto-add /32)
	require.NoError(t, acl.AddNetwork("192.168.1.1"))
	networks = acl.ListNetworks()
	assert.Len(t, networks, 2)

	// Add duplicate (should be no-op)
	require.NoError(t, acl.AddNetwork("10.0.0.0/24"))
	networks = acl.ListNetworks()
	assert.Len(t, networks, 2)

	// Remove network
	require.NoError(t, acl.RemoveNetwork("10.0.0.0/24"))
	networks = acl.ListNetworks()
	assert.Len(t, networks, 1)

	// Remove non-existent
	err = acl.RemoveNetwork("172.16.0.0/16")
	assert.Error(t, err)

	// Invalid CIDR
	err = acl.AddNetwork("not-a-cidr")
	assert.Error(t, err)
}

func TestDynamicACL_Fail2Ban(t *testing.T) {
	acl, err := NewDynamicACL(Config{
		MaxFailedAttempts: 3,
		BanDuration:       100 * time.Millisecond,
	})
	require.NoError(t, err)
	defer acl.Close()

	ip := "10.0.0.1"

	// First two failures should not ban
	assert.False(t, acl.RecordFailure(ip))
	assert.False(t, acl.RecordFailure(ip))
	assert.False(t, acl.IsBanned(ip))

	// Third failure triggers ban
	assert.True(t, acl.RecordFailure(ip))
	assert.True(t, acl.IsBanned(ip))

	// Wait for ban to expire
	time.Sleep(150 * time.Millisecond)
	assert.False(t, acl.IsBanned(ip))
}

func TestDynamicACL_ManualBanUnban(t *testing.T) {
	acl, err := NewDynamicACL(Config{BanDuration: time.Hour})
	require.NoError(t, err)
	defer acl.Close()

	ip := "5.6.7.8"
	assert.False(t, acl.IsBanned(ip))

	acl.Ban(ip)
	assert.True(t, acl.IsBanned(ip))

	acl.Unban(ip)
	assert.False(t, acl.IsBanned(ip))
}

func TestDynamicACL_ListBanned(t *testing.T) {
	acl, err := NewDynamicACL(Config{BanDuration: time.Hour})
	require.NoError(t, err)
	defer acl.Close()

	acl.Ban("1.2.3.4")
	acl.Ban("5.6.7.8")

	banned := acl.ListBanned()
	assert.Len(t, banned, 2)
	assert.Contains(t, banned, "1.2.3.4")
	assert.Contains(t, banned, "5.6.7.8")
}

func TestDynamicACL_Middleware_BannedIP(t *testing.T) {
	acl, err := NewDynamicACL(Config{BanDuration: time.Hour})
	require.NoError(t, err)
	defer acl.Close()

	acl.Ban("10.0.0.1")

	handler := acl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDynamicACL_Middleware_Whitelist(t *testing.T) {
	acl, err := NewDynamicACL(Config{InitialCIDRs: "10.0.0.0/24"})
	require.NoError(t, err)
	defer acl.Close()

	handler := acl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed IP
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.5:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Blocked IP
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestDynamicACL_Middleware_NoWhitelist(t *testing.T) {
	acl, err := NewDynamicACL(Config{})
	require.NoError(t, err)
	defer acl.Close()

	handler := acl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// All IPs should pass when no whitelist configured
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "1.2.3.4:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDynamicACL_Middleware_HealthzBypass(t *testing.T) {
	acl, err := NewDynamicACL(Config{InitialCIDRs: "10.0.0.0/24"})
	require.NoError(t, err)
	defer acl.Close()

	handler := acl.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// /healthz should bypass ACL
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.RemoteAddr = "192.168.1.1:12345"
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestDynamicACL_TimeWindow(t *testing.T) {
	// Create ACL with a window that's currently active
	now := time.Now()
	startH := now.Hour()
	endH := (now.Hour() + 2) % 24
	start := &timeOfDay{Hour: startH, Minute: 0}
	end := &timeOfDay{Hour: endH, Minute: 0}

	acl, err := NewDynamicACL(Config{})
	require.NoError(t, err)
	defer acl.Close()

	acl.windowStart = start
	acl.windowEnd = end
	acl.windowTZ = time.Local

	assert.True(t, acl.isInTimeWindow())

	// Set window to a time that's NOT now
	pastH := (now.Hour() + 12) % 24
	pastEndH := (pastH + 1) % 24
	acl.windowStart = &timeOfDay{Hour: pastH, Minute: 0}
	acl.windowEnd = &timeOfDay{Hour: pastEndH, Minute: 0}

	assert.False(t, acl.isInTimeWindow())
}

func TestDynamicACL_EventHandler(t *testing.T) {
	acl, err := NewDynamicACL(Config{BanDuration: time.Hour})
	require.NoError(t, err)
	defer acl.Close()

	var events []ACLEvent
	var mu sync.Mutex

	acl.SetEventHandler(func(evt ACLEvent) {
		mu.Lock()
		events = append(events, evt)
		mu.Unlock()
	})

	acl.Ban("1.2.3.4")

	// Give the goroutine time to deliver
	time.Sleep(50 * time.Millisecond)

	mu.Lock()
	require.Len(t, events, 1)
	assert.Equal(t, EventIPBanned, events[0].Type)
	assert.Equal(t, "1.2.3.4", events[0].IP)
	mu.Unlock()
}

func TestDynamicACL_ConcurrentAccess(t *testing.T) {
	acl, err := NewDynamicACL(Config{
		MaxFailedAttempts: 100,
		BanDuration:       time.Hour,
	})
	require.NoError(t, err)
	defer acl.Close()

	var wg sync.WaitGroup

	// Concurrent whitelist modifications
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cidr := fmt.Sprintf("10.%d.0.0/24", i)
			_ = acl.AddNetwork(cidr)
		}(i)
	}

	// Concurrent failure recording
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.0.%d", i)
			acl.RecordFailure(ip)
		}(i)
	}

	// Concurrent ban checks
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ip := fmt.Sprintf("192.168.0.%d", i)
			acl.IsBanned(ip)
		}(i)
	}

	wg.Wait()

	networks := acl.ListNetworks()
	assert.Len(t, networks, 50)
}

func TestParseTimeOfDay(t *testing.T) {
	tests := []struct {
		input    string
		wantH    int
		wantM    int
		wantErr  bool
	}{
		{"09:00", 9, 0, false},
		{"23:59", 23, 59, false},
		{"00:00", 0, 0, false},
		{"", 0, 0, false},
		{"25:00", 0, 0, true},
		{"12:60", 0, 0, true},
		{"invalid", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tod, err := parseTimeOfDay(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.input == "" {
				assert.Nil(t, tod)
				return
			}
			assert.Equal(t, tt.wantH, tod.Hour)
			assert.Equal(t, tt.wantM, tod.Minute)
		})
	}
}
