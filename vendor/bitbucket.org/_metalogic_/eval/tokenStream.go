package eval

type tokenStream struct {
	tokens      []ExpressionToken
	index       int
	tokenLength int
}

func newTokenStream(tokens []ExpressionToken) *tokenStream {

	var ret *tokenStream

	ret = new(tokenStream)
	ret.tokens = tokens
	ret.tokenLength = len(tokens)
	return ret
}

func (expr *tokenStream) rewind() {
	expr.index--
}

func (expr *tokenStream) next() ExpressionToken {
	var token ExpressionToken

	token = expr.tokens[expr.index]

	expr.index++
	return token
}

func (expr tokenStream) hasNext() bool {
	return expr.index < expr.tokenLength
}
