package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"
)

func TestHexToBase64(t *testing.T) {
	tst := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	out, err := HexToBase64(tst)
	if err != nil {
		t.Error(err)
	}
	if out != "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" {
		t.Fail()
	}
}
func TestFixedXOR(t *testing.T) {
	s1 := "1c0111001f010100061a024b53535009181c"
	s2 := "686974207468652062756c6c277320657965"
	out, err := FixedXORString(s1, s2)
	if err != nil {
		t.Error(err)
	}
	if out != "746865206b696420646f6e277420706c6179" {
		t.Fail()
	}

}
func TestOneByteXOR(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	decoded, err := hex.DecodeString(input)
	if err != nil {
		t.Error(err)
	}
	decrypted, _, _, err := OneByteXOR(decoded)
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%s\n", decrypted)
}

func TestOneByteXORLines(t *testing.T) {
	infile := "4.txt"
	_, err := OneByteXORLines(infile)
	if err != nil {
		t.Error(err)
	}

}
func TestRepeatingKeyXOR(t *testing.T) {
	input1 := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`
	key := "ICE"
	encrypted := RepeatingKeyXORAsHex([]byte(input1), []byte(key))
	if encrypted != `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f` {
		t.Fatal(encrypted)
	}
}
func TestHamming(t *testing.T) {
	input1 := []byte("this is a test")
	input2 := []byte("wokka wokka!!!")
	dist := hamming(input1, input2)
	if dist != 37 {
		t.Fail()
	}
}

func TestBreakingXOR(t *testing.T) {
	input, err := ioutil.ReadFile("6.txt")
	if err != nil {
		t.Error(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(input))

	if err != nil {
		t.Error(err)
	}
	key := CrackXORKey(decoded)

	fmt.Printf("Key: %s\n", key)
	fmt.Printf("Decrypted: %s", RepeatingKeyXOR(decoded, key))
}

func TestDecryptECB(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")
	input, err := ioutil.ReadFile("7.txt")
	if err != nil {
		t.Error(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(string(input))
	if err != nil {
		panic(err)
	}
	decrypted := DecryptECB(decoded, key)
	fmt.Printf("%s\n", decrypted)
}

func TestDetectECB(t *testing.T) {
	input, err := os.Open("8.txt")
	if err != nil {
		t.Error(err)
	}
	defer input.Close()
	scanner := bufio.NewScanner(input)
	index := 0
	for scanner.Scan() {
		decoded, err := hex.DecodeString(scanner.Text())
		if err != nil {
			t.Error(err)
		}
		isECB := DetectECB(decoded, 16)
		if isECB {
			fmt.Printf("ECB at entry %d\n ", index)
			break
		}
		index++
	}
}
