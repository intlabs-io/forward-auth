package eval

import "fmt"

// OperatorSymbol represents the valid symbols for operators.
type OperatorSymbol int

const (
	VALUE OperatorSymbol = iota
	LITERAL
	NOOP
	EQ
	NEQ
	GT
	LT
	GTE
	LTE
	REQ
	NREQ
	IN

	AND
	OR

	PLUS
	MINUS
	BITWISE_AND
	BITWISE_OR
	BITWISE_XOR
	BITWISE_LSHIFT
	BITWISE_RSHIFT
	MULTIPLY
	DIVIDE
	MODULUS
	EXPONENT

	NEGATE
	INVERT
	BITWISE_NOT

	TERNARY_TRUE
	TERNARY_FALSE
	COALESCE

	FUNCTIONAL
	ACCESS
	SEPARATE

	CONTAINS_IN
	ENDSWITH_IN
	STARTSWITH_IN
)

type operatorPrecedence int

const (
	noopPrecedence operatorPrecedence = iota
	valuePrecedence
	functionalPrecedence
	prefixPrecedence
	exponentialPrecedence
	additivePrecedence
	bitwisePrecedence
	bitwiseShiftPrecedence
	multiplicativePrecedence
	comparatorPrecedence
	ternaryPrecedence
	logicalAndPrecedence
	logicalOrPrecedence
	separatePrecedence
)

func findOperatorPrecedenceForSymbol(symbol OperatorSymbol) operatorPrecedence {

	switch symbol {
	case NOOP:
		return noopPrecedence
	case VALUE:
		return valuePrecedence
	case EQ:
		fallthrough
	case NEQ:
		fallthrough
	case GT:
		fallthrough
	case LT:
		fallthrough
	case GTE:
		fallthrough
	case LTE:
		fallthrough
	case REQ:
		fallthrough
	case NREQ:
		fallthrough
	case CONTAINS_IN:
		fallthrough
	case ENDSWITH_IN:
		fallthrough
	case STARTSWITH_IN:
		fallthrough
	case IN:
		return comparatorPrecedence
	case AND:
		return logicalAndPrecedence
	case OR:
		return logicalOrPrecedence
	case BITWISE_AND:
		fallthrough
	case BITWISE_OR:
		fallthrough
	case BITWISE_XOR:
		return bitwisePrecedence
	case BITWISE_LSHIFT:
		fallthrough
	case BITWISE_RSHIFT:
		return bitwiseShiftPrecedence
	case PLUS:
		fallthrough
	case MINUS:
		return additivePrecedence
	case MULTIPLY:
		fallthrough
	case DIVIDE:
		fallthrough
	case MODULUS:
		return multiplicativePrecedence
	case EXPONENT:
		return exponentialPrecedence
	case BITWISE_NOT:
		fallthrough
	case NEGATE:
		fallthrough
	case INVERT:
		return prefixPrecedence
	case COALESCE:
		fallthrough
	case TERNARY_TRUE:
		fallthrough
	case TERNARY_FALSE:
		return ternaryPrecedence
	case ACCESS:
		fallthrough
	case FUNCTIONAL:
		return functionalPrecedence
	case SEPARATE:
		return separatePrecedence
	}

	return valuePrecedence
}

// Map of all valid comparators, and their string equivalents.
// Used during parsing of expressions to determine if a symbol is, in fact, a comparator.
// Also used during evaluation to determine exactly which comparator is being used.
var comparatorSymbols = map[string]OperatorSymbol{
	"==":         EQ,
	"!=":         NEQ,
	">":          GT,
	">=":         GTE,
	"<":          LT,
	"<=":         LTE,
	"=~":         REQ,
	"!~":         NREQ,
	"in":         IN,
	"contains":   CONTAINS_IN,
	"endsWith":   ENDSWITH_IN,
	"startsWith": STARTSWITH_IN,
}

var logicalSymbols = map[string]OperatorSymbol{
	"&&": AND,
	"||": OR,
}

var bitwiseSymbols = map[string]OperatorSymbol{
	"^": BITWISE_XOR,
	"&": BITWISE_AND,
	"|": BITWISE_OR,
}

var bitwiseShiftSymbols = map[string]OperatorSymbol{
	">>": BITWISE_RSHIFT,
	"<<": BITWISE_LSHIFT,
}

var additiveSymbols = map[string]OperatorSymbol{
	"+": PLUS,
	"-": MINUS,
}

var multiplicativeSymbols = map[string]OperatorSymbol{
	"*": MULTIPLY,
	"/": DIVIDE,
	"%": MODULUS,
}

var exponentialSymbolsS = map[string]OperatorSymbol{
	"**": EXPONENT,
}

var prefixSymbols = map[string]OperatorSymbol{
	"-": NEGATE,
	"!": INVERT,
	"~": BITWISE_NOT,
}

var ternarySymbols = map[string]OperatorSymbol{
	"?":  TERNARY_TRUE,
	":":  TERNARY_FALSE,
	"??": COALESCE,
}

// this is defined separately from additiveSymbols et al because it's needed for parsing, not stage planning.
var modifierSymbols = map[string]OperatorSymbol{
	"+":  PLUS,
	"-":  MINUS,
	"*":  MULTIPLY,
	"/":  DIVIDE,
	"%":  MODULUS,
	"**": EXPONENT,
	"&":  BITWISE_AND,
	"|":  BITWISE_OR,
	"^":  BITWISE_XOR,
	">>": BITWISE_RSHIFT,
	"<<": BITWISE_LSHIFT,
}

var separatorSymbols = map[string]OperatorSymbol{
	",": SEPARATE,
}

// IsModifierType returns true if this operator is contained by the given array of candidate symbols.
// False otherwise.
func (sym OperatorSymbol) IsModifierType(candidate []OperatorSymbol) bool {

	for _, symbolType := range candidate {
		if sym == symbolType {
			return true
		}
	}

	return false
}

// String is generally used when formatting type check errors.
// We could store the stringified symbol somewhere else and not require a duplicated codeblock to translate
// OperatorSymbol to string, but that would require more memory, and another field somewhere.
// Adding operators is rare enough that we just stringify it here instead.
func (sym OperatorSymbol) String() string {

	switch sym {
	case NOOP:
		return "NOOP"
	case VALUE:
		return "VALUE"
	case LITERAL:
		return "LITERAL"
	case EQ:
		return "="
	case NEQ:
		return "!="
	case GT:
		return ">"
	case LT:
		return "<"
	case GTE:
		return ">="
	case LTE:
		return "<="
	case REQ:
		return "=~"
	case NREQ:
		return "!~"
	case AND:
		return "&&"
	case OR:
		return "||"
	case IN:
		return "in"
	case CONTAINS_IN:
		return "contains"
	case ENDSWITH_IN:
		return "endsWith"
	case STARTSWITH_IN:
		return "startsWith"
	case BITWISE_AND:
		return "&"
	case BITWISE_OR:
		return "|"
	case BITWISE_XOR:
		return "^"
	case BITWISE_LSHIFT:
		return "<<"
	case BITWISE_RSHIFT:
		return ">>"
	case PLUS:
		return "+"
	case MINUS:
		return "-"
	case MULTIPLY:
		return "*"
	case DIVIDE:
		return "/"
	case MODULUS:
		return "%"
	case EXPONENT:
		return "**"
	case NEGATE:
		return "-"
	case INVERT:
		return "!"
	case BITWISE_NOT:
		return "~"
	case TERNARY_TRUE:
		return "?"
	case TERNARY_FALSE:
		return ":"
	case COALESCE:
		return "??"
	case FUNCTIONAL:
		return "FUNCTION"
	case ACCESS:
		return "ACCESS"
	case SEPARATE:
		return ","
	}
	return fmt.Sprintf("INVALID OPERATOR %d", sym)
}

func Symbol(symbol string) (op OperatorSymbol, err error) {

	switch symbol {
	case "NOOP":
		return NOOP, nil
	case "VALUE":
		return VALUE, nil
	case "EQ":
		return EQ, nil
	case "NEQ":
		return NEQ, nil
	case "GT":
		return GT, nil
	case "LT":
		return LT, nil
	case "GTE":
		return GTE, nil
	case "LTE":
		return LTE, nil
	case "REQ":
		return REQ, nil
	case "NREQ":
		return NREQ, nil
	case "AND":
		return AND, nil
	case "OR":
		return OR, nil
	case "IN":
		return IN, nil
	case "CONTAINS_IN":
		return CONTAINS_IN, nil
	case "ENDSWITH_IN":
		return ENDSWITH_IN, nil
	case "STARTSWITH_IN":
		return STARTSWITH_IN, nil
	case "BITWISE_AND":
		return BITWISE_AND, nil
	case "BITWISE_OR":
		return BITWISE_OR, nil
	case "BITWISE_XOR":
		return BITWISE_XOR, nil
	case "BITWISE_LSHIFT":
		return BITWISE_LSHIFT, nil
	case "BITWISE_RSHIFT":
		return BITWISE_RSHIFT, nil
	case "PLUS":
		return PLUS, nil
	case "MINUS":
		return MINUS, nil
	case "MULTIPLY":
		return MULTIPLY, nil
	case "DIVIDE":
		return DIVIDE, nil
	case "MODULUS":
		return MODULUS, nil
	case "EXPONENT":
		return EXPONENT, nil
	case "NEGATE":
		return NEGATE, nil
	case "INVERT":
		return INVERT, nil
	case "BITWISE_NOT":
		return BITWISE_NOT, nil
	case "TERNARY_TRUE":
		return TERNARY_TRUE, nil
	case "TERNARY_FALSE":
		return TERNARY_FALSE, nil
	case "COALESCE":
		return COALESCE, nil
	}
	return op, fmt.Errorf("%s is not a valid operator", symbol)
}
