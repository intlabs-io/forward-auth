package authn

// Classification encapsulates a security classification for a given
// authority (eg. CLASSIFIED, SECRET, TOP-SECRET...)
type Classification struct {
	Authority string `json:"authority"`
	Level     string `json:"level"`
}

