package config

import "time"

const (
	DefaultPort         = "22"
	DefaultIdentityFile = "~/.ssh/id_rsa"
	DefaultAllowedIP    = "0.0.0.0/0"
	DefaultTimeout      = 15 * time.Second
)
