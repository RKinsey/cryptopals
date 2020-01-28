package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"unicode"
)

func HexToBase64(hexs string) (string, error) {
	s, err := hex.DecodeString(hexs)
	if err != nil {
		return "", err
	}
	fmt.Printf("%s\n", string(s))
	return base64.StdEncoding.EncodeToString(s), nil
}
func FixedXOR(hex1, hex2 string) (string, error) {
	if len(hex1) != len(hex2) {
		return "", errors.New("inputs are not the same length")
	}
	decoded1, err := hex.DecodeString(hex1)
	if err != nil {
		return "", err
	}
	decoded2, err := hex.DecodeString(hex2)
	if err != nil {
		return "", err
	}
	xored := make([]byte, len(decoded1))
	for i := 0; i < len(xored); i++ {
		xored[i] = decoded1[i] ^ decoded2[i]
	}
	fmt.Printf("First:%s\nSecond:%s\nXORed:%s\n", decoded1, decoded2, xored)
	return hex.EncodeToString(xored), nil
}

func OneByteXOR(input string) (string, error) {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", err
	}
	bestScore := -1
	bestChar := -1

	for char := byte(0x00); char < unicode.MaxASCII; char++ {
		//xored := make([]byte, len(decoded))
		score:=0
		for i, e := range decoded {
			xored=char^e
			switch(char^e){
				case 
			}
			if char^e
			
		}
	}
}
