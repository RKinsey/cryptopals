package cryptopals

import "testing"

import "bytes"

func TestPadPKCS7(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	padded := PadPKCS7(plaintext, 20)
	good := bytes.Equal([]byte("YELLOW SUBMARINE\x04\x04\x04\x04"), padded)
	if !good {
		t.Fail()
	}
}
