package fauth

// Common defines the common service interface
type Common interface {
	Health() error
	Info() map[string]string
	Stats() string
}

// Store defines the storage interface
type Store interface {
	Common
	ID() string
	Load() (*AccessControls, error)
	Listen(func(*AccessControls) error)
	Close() error
}
