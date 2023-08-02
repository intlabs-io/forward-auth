package acc

type Person struct {
	UserName     string   `json:"userName,omitempty"`
	Email        string   `json:"email"`
	Password     string   `json:"password"`
	Declarations []string `json:"declarations"`
}
