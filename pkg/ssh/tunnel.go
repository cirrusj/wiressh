package ssh

import (
	"github.com/cirrusj/wiressh/pkg/direct"
	"github.com/cirrusj/wiressh/pkg/manager"
	"github.com/cirrusj/wiressh/pkg/tailscale"
	"github.com/cirrusj/wiressh/pkg/wireguard"
)

// Dependency injection for tunnel manager constructors (for testing)
var (
	WireGuardManagerCtor func(debug bool) manager.Manager = func(debug bool) manager.Manager { return wireguard.NewManager(debug) }
	TailscaleManagerCtor func(debug bool) manager.Manager = func(debug bool) manager.Manager { return tailscale.NewManager(debug) }
	DirectManagerCtor    func(debug bool) manager.Manager = func(debug bool) manager.Manager { return direct.NewManager(debug) }
)
