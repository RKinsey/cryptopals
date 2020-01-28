package cryptopals

import (
	"fmt"
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
	out, err := FixedXOR(s1, s2)
	if err != nil {
		t.Error(err)
	}
	if out != "746865206b696420646f6e277420706c6179" {
		t.Fail()
	}

}
func TestOneByteXOR(t *testing.T) {
	input := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	decrypted, _, err := OneByteXOR(input)
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
	encrypted := RepeatingKeyXOR(input1, key)
	if encrypted != `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f` {
		t.Fatal(encrypted)
	}
}
