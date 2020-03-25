package cryptopals

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
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
	test_txt := []byte(strings.Repeat("a", 16*5))
	for i := 0; i < 100; i++ {
		if DetectECB(EncryptionOracle(test_txt), 16) {
			ebc += 1
		} else {
			cbc += 1
		}
	}
	fmt.Printf("EBC: %d CBC: %d", ebc, cbc)
}

func TestByteAtATimeECBDecryption(t *testing.T) {
	pretextString := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	pretext, err := base64.StdEncoding.DecodeString(pretextString)
	if err != nil {
		t.Error(err)
	}
	oracle := MakeConsistentECBOracle(pretext)
	dec := SimpleECBDecrypt(oracle)
	fmt.Printf("Decrypted: %s\n", dec)

}

func TestECBCopyPaste(t *testing.T) {
	ParseProfile("foo=bar&baz=qux&zap=zazzle")
	user := ECBCutAndPaste("foo@bar.com")
	fmt.Printf("%t\n", CheckAdmin(user))
}
func TestHardECBDecrypt(t *testing.T) {
	//skip for now
}

func TestValidatePKCS7(t *testing.T) {
	a := []byte("ICE ICE BABY\x04\x04\x04\x04")
	err := ValidatePKCS7(a)
	if err != nil {
		t.Errorf("Padding check failed for %s\n", a)
	}

	a = []byte("ICE ICE BABY\x05\x05\x05\x05")
	err = ValidatePKCS7(a)
	if err == nil {
		t.Error(err)
	}

	a = []byte("ICE ICE BABY\x01\x02\x03\x04")
	err = ValidatePKCS7(a)
	if err == nil {
		t.Error(err)
	}
}

func TestBitflippingAttack(t *testing.T) {
	enc, check := MakeBitflippingOracle()
	if check(enc(";admin=true;")) {
		t.Error("Oracle should not accept \";admin=true;\"")
	}
	if !CBCBitFlip(enc, check) {
		t.FailNow()
	}
}
