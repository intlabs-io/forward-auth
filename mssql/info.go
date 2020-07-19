package mssql

// Info represents information about the runtime environment
// maybe add some details about memory, network usage, etc
type info struct {
        Hostname string `json:"hostname"`
        Database string `json:"database"`
        MSSql    string `json:"mssql"`
        LogLevel string `json:"logLevel"`
}

