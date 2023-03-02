package types

type ErrorMessage struct {
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

type Message struct {
	Message string `json:"message"`
}
