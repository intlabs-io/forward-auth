package eval

// ExpressionToken represents a single parsed token.
type ExpressionToken struct {
	Kind  TokenKind
	Value interface{}
}
