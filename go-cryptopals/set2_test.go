package cryptopals

import (
	"bytes"
	"fmt"
	"testing"
)

func TestPadPKCS7(t *testing.T) {
	plaintext := []byte("YELLOW SUBMARINE")
	padded := PadPKCS7(plaintext, 20)
	good := bytes.Equal([]byte("YELLOW SUBMARINE\x04\x04\x04\x04"), padded)
	if !good {

		t.FailNow()
	}
}

func TestCBC(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, len(key))

	test := []byte("This is 32 bytes long and 2 blox")
	fmt.Printf("%s\n", test)
	encryptionTest := EncryptCBC(test, iv, key)
	fmt.Printf("Test Encrypt: %s\n", encryptionTest)
	decrypted := DecryptCBC(encryptionTest, iv, key)
	fmt.Printf("Test Decrypt: %s\n", decrypted)
	if !bytes.Equal(test, decrypted) {
		t.Logf("Decryption failed")
		t.FailNow()
	}
	input, err := ReadBase64File("10.txt")
	if err != nil {
		t.Error(err)
	}
	iv = make([]byte, len(key))
	fmt.Printf("%s\n", DecryptCBC(input, iv, key))

}

func TestECB_CBC_Oracle(t *testing.T) {
	var cbc, ebc uint
	for i := 0; i < 100; i++ {
		if DetectECBorCBC(EncryptionOracle())
	}
}
