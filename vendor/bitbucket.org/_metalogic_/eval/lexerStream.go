package eval

type lexerStream struct {
	source   []rune
	position int
	length   int
}

func newLexerStream(source string) *lexerStream {

	var ret *lexerStream
	var runes []rune

	for _, character := range source {
		runes = append(runes, character)
	}

	ret = new(lexerStream)
	ret.source = runes
	ret.length = len(runes)
	return ret
}

func (stream *lexerStream) readCharacter() rune {

	var character rune

	character = stream.source[stream.position]
	stream.position++
	return character
}

func (stream *lexerStream) rewind(amount int) {
	stream.position -= amount
}

func (stream lexerStream) canRead() bool {
	return stream.position < stream.length
}
