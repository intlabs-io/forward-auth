package eval

import (
	"encoding/json"
)

// NewEvaluableExpressionFromJSON constructs an EvaluableExpression from a JSON
// object representation of an Abstract Syntax Tree [ast]
// This is useful in cases where an outside processor is generating an AST.
func NewEvaluableExpressionFromJSON(ast []byte) (expr *EvaluableExpression, err error) {

	expr = new(EvaluableExpression)
	expr.QueryDateFormat = isoDateFormat

	expr.ChecksTypes = true

	tree := &EvaluationTree{}

	err = json.Unmarshal(ast, tree)
	if err != nil {
		return expr, err
	}
	expr.evaluationTree = tree
	return expr, nil
}

// NewEvaluableExpressionFromAST constructs an EvaluableExpression from a JSON
// object representation of an Abstract Syntax Tree [ast]
// This is useful in cases where an outside processor is generating an AST.
func NewEvaluableExpressionFromAST(ast *EvaluationTree) (expr *EvaluableExpression, err error) {

	expr = new(EvaluableExpression)
	expr.QueryDateFormat = isoDateFormat

	expr.ChecksTypes = true
	expr.evaluationTree = ast
	return expr, nil
}

// NewEvaluableExpressionFromASTWithFunctions constructs an EvaluableExpression from a JSON
// object representation of an Abstract Syntax Tree [ast]
// This is useful in cases where an outside processor is generating an AST.
func NewEvaluableExpressionFromASTWithFunctions(ast *EvaluationTree, functions map[string]ExpressionFunction) (expr *EvaluableExpression, err error) {

	expr = new(EvaluableExpression)
	expr.QueryDateFormat = isoDateFormat

	expr.ChecksTypes = true
	expr.evaluationTree = ast
	return expr, nil
}
