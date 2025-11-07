package app

import (
	"cosmossdk.io/depinject"
)

// AppConfig returns the default app config
func AppConfig() depinject.Config {
	return depinject.Configs()
}

