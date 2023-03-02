package eval

import (
	"bytes"
)

/*
	Holds a series of "transactions" which represent each token as it is output by an outputter (such as ToSQLQuery()).
	Some outputs (such as SQL) require a function call or non-c-like syntax to represent an expression.
	To accomplish this, this struct keeps track of each translated token as it is output, and can return and rollback those transactions.
*/
type expressionOutputStream struct {
	transactions []string
}

func (stream *expressionOutputStream) add(transaction string) {
	stream.transactions = append(stream.transactions, transaction)
}

func (stream *expressionOutputStream) rollback() string {

	index := len(stream.transactions) - 1
	ret := stream.transactions[index]

	stream.transactions = stream.transactions[:index]
	return ret
}

func (stream *expressionOutputStream) createString(delimiter string) string {

	var retBuffer bytes.Buffer
	var transaction string

	penultimate := len(stream.transactions) - 1

	for i := 0; i < penultimate; i++ {

		transaction = stream.transactions[i]

		retBuffer.WriteString(transaction)
		retBuffer.WriteString(delimiter)
	}
	retBuffer.WriteString(stream.transactions[penultimate])

	return retBuffer.String()
}
