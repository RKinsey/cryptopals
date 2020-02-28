package cryptopals

import (
	"crypto/aes"
	crand "crypto/rand"
	"math/rand"
)

func MakeBytePadding(padval byte, padlen int) []byte {
	padding := make([]byte, padlen)
	for i := range padding {
		padding[i] = padval
	}
	return padding
}
func PadPKCS7(plaintext []byte, blocksize int) []byte {
	if len(plaintext)%blocksize == 0 {
		return plaintext
	}
	padlen := blocksize - len(plaintext)%blocksize
	padding := MakeBytePadding(byte(padlen), padlen)
	return append(plaintext, padding...)
}
func checkCBC(err error, blocksize, ivLen, modLen int) {
	if err != nil {
		panic(err)
	}
	if ivLen != blocksize {
		panic("IV not of blocksize")
	}
	if modLen != 0 {
		panic("input not a multiple of blocksize")
	}
}
func EncryptCBC(plaintext, iv, key []byte) []byte {
	cbc, err := aes.NewCipher(key)
	blocksize := cbc.BlockSize()
	checkCBC(err, blocksize, len(iv), len(plaintext)%blocksize)

	toRet := make([]byte, len(plaintext))
	lastBlock := iv
	for i := 0; i < len(plaintext)/blocksize; i++ {
		xored, _ := XORSlices(lastBlock, plaintext[i*blocksize:(i+1)*blocksize])
		cbc.Encrypt(toRet[i*blocksize:], xored)
		lastBlock = toRet[i*blocksize : (i+1)*blocksize]
	}
	return toRet
}

func DecryptCBC(ciphertext, iv, key []byte) []byte {
	cbc, err := aes.NewCipher(key)
	blocksize := cbc.BlockSize()
	checkCBC(err, blocksize, len(iv), len(ciphertext)%blocksize)
	toRet := make([]byte, 0, len(ciphertext))
	lastBlock := iv
	for i := 0; i < len(ciphertext)/blocksize; i++ {
		toXor := make([]byte, blocksize)
		cbc.Decrypt(toXor, ciphertext[i*blocksize:])
		xored, _ := XORSlices(lastBlock, toXor)
		toRet = append(toRet, xored...)
		lastBlock = ciphertext[i*blocksize : (i+1)*blocksize]
	}
	return toRet
}
func EncryptECB(plaintext, key []byte) []byte {
	ecb, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	blocksize := ecb.BlockSize()
	if len(plaintext)%blocksize != 0 {
		panic("input not multiple of blocksize")
	}
	toRet := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext)/blocksize; i++ {
		ecb.Encrypt(toRet[i*blocksize:], plaintext[i*blocksize:])
	}
	return toRet
}

func RandomAESKey() []byte {
	key := make([]byte, 16)
	crand.Read(key)
	return key
}

func EncryptionOracle(plaintext []byte) []byte {
	before := make([]byte, 5+rand.Intn(5))
	after := make([]byte, 5+rand.Intn(5))
	crand.Read(before)
	crand.Read(after)
	toEncrypt := append(append(before, plaintext...), after...)
	if rand.Uint32()%2 == 0 {
		iv := make([]byte, 16)
		crand.Read(iv)
		return EncryptCBC(toEncrypt, iv, RandomAESKey())
	} else {
		return EncryptECB(toEncrypt, RandomAESKey())
	}
}
func DetectECBorCBC(ciphertext []byte) bool {
	if DetectECB(ciphertext) {
		return true
	} else {
		return false
	}
}
