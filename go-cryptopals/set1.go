package cryptopals

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
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

var frequents = map[string]float64{
	"e": 12.02,
	"t": 9.1,
	"a": 8.12,
	"o": 7.68,
	"i": 7.31,
	"n": 6.95,
	"s": 6.28,
	"r": 6.02,
	"h": 5.92,
	"d": 4.32,
	"l": 3.98,
	"u": 2.88,
	"c": 2.71,
	"m": 2.61,
	"f": 2.3,
	"y": 2.11,
	"w": 2.09,
	"g": 2.03,
	"p": 1.82,
	"b": 1.49,
	"v": 1.11,
	"k": .69,
	"x": .17,
	"q": .11,
	"j": .1,
	"z": .07,
}

func OneByteXOR(input string) (string, float64, error) {
	decoded, err := hex.DecodeString(input)
	if err != nil {
		return "", -1, err
	}
	bestScore := 0.
	var bestDecrypt []byte
	//not clear if printable or not, assuming in ASCII
	for char := byte(0x00); char < unicode.MaxASCII; char++ {
		//xored := make([]byte, len(decoded))
		score := 0.
		decrypted := make([]byte, len(decoded))
		//badtext:=false
		for i, e := range decoded {
			decrypted[i] = char ^ e
			xored := decrypted[i]
			val, common := frequents[strings.ToLower(string(xored))]
			badtext := false
			switch {
			case common:
				score += val
			case 32 > xored || xored > 126:
				badtext = true
				break
			case (48 <= xored && 57 >= xored) || (xored == 32): //numbers and space
				score += .1
			default:
				score -= 1
			}
			if badtext {
				break
			}
		}

		if score > bestScore {
			//fmt.Printf("%s:%f\n", decrypted, score)
			bestScore = score
			bestDecrypt = decrypted
		}
	}
	return string(bestDecrypt), bestScore, nil
}
func OneByteXORLines(inputfile string) (string, error) {
	input, err := os.Open(inputfile)
	if err != nil {
		return "", err
	}
	defer input.Close()
	scanner := bufio.NewScanner(input)
	bestDecrypt := ""
	bestScore := 0.
	index := 0
	bestIndex := 0
	for scanner.Scan() {
		decrypted, score, err := OneByteXOR(scanner.Text())
		if err != nil {
			return "", nil
		} else if score > bestScore && err == nil {
			bestDecrypt = decrypted
			bestScore = score
			bestIndex = index
		}
		index++
	}
	fmt.Printf("Best: %s\nScore: %f\nAt Line:%d\n", bestDecrypt, bestScore, bestIndex)
	return bestDecrypt, nil
}
func RepeatingKeyXOR(input, key string) string {
	toret := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		toret[i] = input[i] ^ key[i%len(key)]
	}
	return string(toret)
}
