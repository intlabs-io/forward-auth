package file

// Info represents information about the runtime environment
// maybe add some details about memory, network usage, etc
type info struct {
	Hostname  string `json:"hostname"`
	Directory string `json:"directory"`
	LogLevel  string `json:"logLevel"`
}
