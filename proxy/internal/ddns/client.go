package ddns

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	duckDNSAPI     = "https://www.duckdns.org/update"
	updateInterval = 5 * time.Minute
)

// Client updates a DuckDNS record periodically.
type Client struct {
	subdomain  string
	token      string
	domain     string
	stop       chan struct{}
	stopOnce   sync.Once
	httpClient *http.Client
	apiURL     string
}

// New creates a Client for the given subdomain and token.
// Returns nil if either is empty.
func New(subdomain, token string) *Client {
	if subdomain == "" || token == "" {
		return nil
	}
	return &Client{
		subdomain:  subdomain,
		token:      token,
		domain:     subdomain + ".duckdns.org",
		stop:       make(chan struct{}),
		httpClient: http.DefaultClient,
		apiURL:     duckDNSAPI,
	}
}

// Domain returns the fully-qualified domain name managed by this client.
func (c *Client) Domain() string {
	if c == nil {
		return ""
	}
	return c.domain
}

// Start performs an immediate update then schedules periodic updates.
func (c *Client) Start() {
	if c == nil {
		return
	}
	go func() {
		if err := c.update(); err != nil {
			log.Printf("ddns: initial update failed: %v", err)
		}
		ticker := time.NewTicker(updateInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				if err := c.update(); err != nil {
					log.Printf("ddns: periodic update failed: %v", err)
				}
			case <-c.stop:
				return
			}
		}
	}()
}

// Stop cancels the periodic update goroutine.
func (c *Client) Stop() {
	if c == nil {
		return
	}
	c.stopOnce.Do(func() {
		close(c.stop)
	})
}

func (c *Client) update() error {
	apiURL := fmt.Sprintf("%s?domains=%s&token=%s&ip=&ipv6=&verbose=true",
		c.apiURL,
		url.QueryEscape(c.subdomain),
		url.QueryEscape(c.token))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	bodyStr := strings.TrimSpace(string(body))
	if !strings.HasPrefix(bodyStr, "OK") {
		return fmt.Errorf("DuckDNS update failed: %s", bodyStr)
	}
	log.Printf("ddns: updated %s", c.domain)
	return nil
}
