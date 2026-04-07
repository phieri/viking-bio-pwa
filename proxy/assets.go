// Package proxy provides embedded static assets for the Viking Bio proxy server.
package proxy

import "embed"

// PublicFS contains the embedded PWA static files from proxy/public.
// Used by the HTTP server to serve the dashboard without requiring the
// public/ directory to be present at runtime (self-contained binary).
//
//go:embed public
var PublicFS embed.FS
