package sniparser

import (
	"bytes"
)

func Fuzz(data []byte) int {
	_, _, err := ReadServerName(bytes.NewReader(data))
	if err != nil {
		return 0
	}
	return 1
}
