package cryptopals

import (
	"bufio"
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
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

func OneByteXOR(decoded []byte) (string, float64, byte, error) {

	bestScore := -1.
	bestChar := byte(0)
	//var bestDecrypt []byte
	var lastStr, bestStr string
	//not clear if printable or not, assuming in ASCII
	for char := byte(0x00); char < ^byte(0); char++ {
		//xored := make([]byte, len(decoded))
		score := 0.
		decrypted := make([]byte, len(decoded))
		badtext := false

		for i, e := range decoded {
			decrypted[i] = char ^ e
			xored := decrypted[i]
			val, common := frequents[strings.ToLower(string(xored))]
			badtext = false
			switch {
			case common:
				score += val
			case xored == 10: //newline but not CR
				score += .1
			case 32 > xored || xored > 126:
				badtext = true
				score = -1
				break
			case (48 <= xored && 57 >= xored) || (xored == 32): //numbers and space
				score += .1
			default:
				score *= .75
			}
			if badtext {
				break
			}

		}
		lastStr = string(decrypted)
		if !badtext && score > bestScore {
			//fmt.Printf("%s:%f\n", decrypted, score)
			bestChar = char
			bestScore = score
			//bestDecrypt = decrypted
			bestStr = lastStr
		}

	}
	return bestStr, bestScore, bestChar, nil
}
func OneByteXORLines(inputfile string) (string, error) {
	input, err := os.Open(inputfile)
	if err != nil {
		return "", err
	}
	defer input.Close()
	scanner := bufio.NewScanner(input)
	bestDecrypt := ""
	bestScore := -1.
	index := 0
	bestIndex := 0
	for scanner.Scan() {
		decoded, err := hex.DecodeString(scanner.Text())
		if err != nil {
			return "", err
		}
		decrypted, score, _, err := OneByteXOR(decoded)
		if err != nil {
			return "", nil
		} else if score > bestScore && err == nil {
			bestDecrypt = decrypted
			bestScore = score
			bestIndex = index
		}
		index++
	}
	fmt.Printf("OneByteXORLines Best: %s\nScore: %f\nAt Line:%d\n", bestDecrypt, bestScore, bestIndex)
	return bestDecrypt, nil
}
func RepeatingKeyXORAsHex(input, key []byte) string {
	return hex.EncodeToString([]byte(RepeatingKeyXOR(input, key)))
}
func RepeatingKeyXOR(input, key []byte) string {
	toret := make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		toret[i] = input[i] ^ key[i%len(key)]
	}
	return string(toret)
}
func hamming(i1, i2 []byte) float64 {
	if len(i1) != len(i2) {
		panic("inputs must be same length")
	}
	distance := 0.
	for i, el1 := range i1 {
		for x := el1 ^ i2[i]; x > 0; x >>= 1 {
			if x&1 != 0 {
				distance += 1
			}
		}
	}
	return distance
}
func FindXORKeySize(input []byte) int {
	best := -1
	bestDist := -1.
	for keysize := 2; keysize <= 40; keysize++ {
		dist := hamming(input[:keysize*4], input[keysize*4:keysize*8]) / 4.
		normDist := dist / float64(keysize)
		if best == -1 || normDist < bestDist {
			best = keysize
			bestDist = normDist
		}
	}
	return best
}
func transpose(blockLen int, input []byte) [][]byte {
	toret := make([][]byte, blockLen)
	for i := range toret {
		toret[i] = make([]byte, 0, len(input)/blockLen+1)
	}
	for i, el := range input {
		toret[i%blockLen] = append(toret[i%blockLen], el)
	}
	return toret
}

func CrackXORKey(input []byte) []byte {

	keylen := FindXORKeySize(input)
	key := make([]byte, keylen)
	transposed := transpose(keylen, input)
	for j, entry := range transposed {
		_, _, ch, err := OneByteXOR(entry)
		if err != nil {
			panic(err)
		}
		key[j] = ch
	}
	return key
}

func DecryptECB(input, key []byte) []byte {
	ecb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blocksize := ecb.BlockSize()
	if len(input)%blocksize != 0 {
		panic("input not multiple of blocksize")
	}
	toRet := make([]byte, len(input))
	for i := 0; i < len(input)/blocksize; i++ {
		ecb.Decrypt(toRet[i*blocksize:], input[i*blocksize:])
	}
	return toRet
}

func DetectECB(input []byte) bool {
	blocksize := 16
	if len(input)%blocksize != 0 {
		panic("input length != blocksize")
	}
	hist := make(map[string]bool)
	for i := 0; i < len(input); i += blocksize {
		curString := string(input[i : i+blocksize])
		if hist[curString] {
			return true
		}
		hist[curString] = true
	}
	return false
}
