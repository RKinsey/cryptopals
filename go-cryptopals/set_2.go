package cryptopals

import (
	"bytes"
	"crypto/aes"
	crand "crypto/rand"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
)

func MakeBytePadding(padval byte, padlen int) []byte {
	padding := make([]byte, padlen)
	for i := range padding {
		padding[i] = padval
	}
	return padding
}
func PadPKCS7(plaintext []byte, blocksize int) []byte {
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
	var toEnc []byte
	for i := 0; i < len(plaintext)/blocksize; i++ {
		toEnc = plaintext[i*blocksize:]
		ecb.Encrypt(toRet[i*blocksize:], toEnc)
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
	toEncrypt = PadPKCS7(toEncrypt, 16)
	e := rand.Uint32()
	if e%2 == 0 {
		iv := make([]byte, 16)
		crand.Read(iv)
		return EncryptCBC(toEncrypt, iv, RandomAESKey())
	} else {
		return EncryptECB(toEncrypt, RandomAESKey())
	}
}
func MakeConsistentECBOracle(uk []byte) func([]byte) []byte {
	key := RandomAESKey()
	unknown := append([]byte(nil), uk...)
	return func(prefix []byte) []byte {
		toEncrypt := append(prefix, unknown...)
		return EncryptECB(PadPKCS7(toEncrypt, 16), key)
	}
}

func SimpleECBDecrypt(oracle func([]byte) []byte) []byte {
	isECB := false
	blockLength := 0
	for size := 1; size <= 256; size *= 2 {
		blockLength += 1
		checktext := bytes.Repeat([]byte("a"), size*2)
		isECB = DetectECB(oracle(checktext)[:size*2], size)
		if isECB {
			blockLength = size
			break
		}
	}
	if blockLength == 0 {
		panic("Not ECB or block length > 256")
	}
	makeDict := func(prefix, known []byte) map[string]byte {
		dict := make(map[string]byte)
		if known != nil {
			prefix = append(prefix, known...)
			prefix = prefix[len(prefix)-blockLength+1:]
		}
		for i := 0; i < 256; i++ {
			pt := append(prefix, byte(i))

			or := oracle(pt)[:blockLength]
			dict[string(or)] = byte(i)
		}
		return dict
	}
	subtext := bytes.Repeat([]byte("a"), blockLength-1)
	firstByteDict := makeDict(subtext, nil)
	encryptedFirstByte := oracle(subtext)[:blockLength]
	firstByte := firstByteDict[string(encryptedFirstByte)]
	fmt.Printf("First byte: %s\n", string(firstByte))
	ciphertextLen := len(oracle([]byte(nil)))
	decrypted := make([]byte, 0, ciphertextLen)
	for i := 0; i < ciphertextLen; i += blockLength {
		//fmt.Printf("Block: %d\n", i)
		for j := blockLength; j > 0; j-- {
			blockPos := blockLength - j
			//fmt.Printf("  Byte: %d\n", j)
			prefix := bytes.Repeat([]byte("a"), j-1)
			currDict := makeDict(prefix, decrypted)
			//fmt.Printf("%v -> %v\n", append(prefix, decrypted[i:i+blockPos]...), oracle(prefix)[i:i+blockLength])
			corrByte := currDict[string(oracle(prefix)[i:i+blockLength])]
			decrypted = append(decrypted, corrByte)
			if blockPos+i >= ciphertextLen {
				break
			}
		}

	}

	return decrypted
}

func ParseProfile(prof string) map[string]string {
	kvs := strings.Split(prof, "&")
	profMap := make(map[string]string)
	for _, kv := range kvs {
		skv := strings.Split(kv, "=")
		profMap[skv[0]] = skv[1]
	}
	fmt.Printf("%s\n", profMap)
	return profMap
}

func ProfileFor(email string) string {
	email = strings.Join(strings.Split(email, "="), "")
	email = strings.Join(strings.Split(email, "&"), "")
	return "email=" + email + "&uid=10&role=user"
}

func CheckAdmin(user map[string]string) bool {
	if role, ok := user["role"]; ok && role != "admin" {
		return false
	}
	return true
}

func MakeECBCutPasteOracle() (
	func(email string) []byte,
	func([]byte) map[string]string) {

	key := RandomAESKey()
	cryptUser := func(email string) []byte {
		return EncryptECB(PadPKCS7([]byte(ProfileFor(email)), 16), key)
	}
	decryptAndParse := func(encrypted []byte) map[string]string {
		return ParseProfile(string(UnpadPKCS7(DecryptECB(encrypted, key))))
	}
	return cryptUser, decryptAndParse
}
func UnpadPKCS7(padded []byte) []byte {
	numToDrop := int(padded[len(padded)-1])
	return padded[:len(padded)-numToDrop]
}
func ECBCutAndPaste(email string) map[string]string {
	encryptOracle, decryptOracle := MakeECBCutPasteOracle()
	//len(email=) == len(uid=xx) == 6
	//len(role=user) == 9
	//len(role=admin) == 10
	//total w/o string == 15
	//admin total w/o string == 16
	//need email that gets user\xC\xC\xC\xC\xC\xC\xC\xC\xC\xC\xC\xC in its own block
	//i.e. 5 chars long (1+len(user))
	//then to pad admin\xB\xB\xB\xB\xB\xB\xB\xB\xB\xB\xB into a block
	//then cut/paste
	userBlock := encryptOracle("aaaaa")
	userBlock = userBlock[len(userBlock)-16:]
	adminArray := append([]byte("aaaaaaaaa admin"), bytes.Repeat([]byte{11}, 11)...)
	adminBlock := encryptOracle(string(adminArray))
	adminBlock = adminBlock[16 : 16*2]
	spacePadding := strings.Repeat(" ", len(email)%4-1)
	toElevate := encryptOracle(email + spacePadding)
	elevated := append(toElevate[:len(toElevate)-16], adminBlock...)
	return decryptOracle(elevated)
}

func MakePaddedOracle(base []byte) func([]byte) []byte {
	key := RandomAESKey()
	unknown := append([]byte(nil), base...)
	prefix := make([]byte, rand.Intn(100))
	return func(input []byte) []byte {
		toEncrypt := append(input, unknown...)
		rand.Read(prefix)
		toEncrypt = append(prefix, toEncrypt...)
		return EncryptECB(PadPKCS7(toEncrypt, 16), key)
	}
}
func HardECBDecrypt(oracle func([]byte) []byte) []byte {

	isECB := false
	blockLength := 0
	for size := 1; size <= 256; size *= 2 {
		blockLength += 1
		checktext := bytes.Repeat([]byte("a"), size*5)
		isECB = DetectECB(oracle(checktext)[size*3:size*5], size)
		if isECB {
			blockLength = size
			break
		}
	}
	if blockLength == 0 {
		panic("Not ECB or block length > 256")
	}
	makeDict := func(prefix, known []byte) map[string]byte {
		dict := make(map[string]byte)
		if known != nil {
			prefix = append(prefix, known...)
			prefix = prefix[len(prefix)-blockLength+1:]
		}
		for i := 0; i < 256; i++ {
			pt := append(prefix, byte(i))

			or := oracle(pt)[:blockLength]
			dict[string(or)] = byte(i)
		}
		return dict
	}
	subtext := bytes.Repeat([]byte("a"), blockLength-1)
	firstByteDict := makeDict(subtext, nil)
	encryptedFirstByte := oracle(subtext)[:blockLength]
	firstByte := firstByteDict[string(encryptedFirstByte)]
	fmt.Printf("First byte: %s\n", string(firstByte))
	ciphertextLen := len(oracle([]byte(nil)))
	decrypted := make([]byte, 0, ciphertextLen)
	for i := 0; i < ciphertextLen; i += blockLength {
		//fmt.Printf("Block: %d\n", i)
		for j := blockLength; j > 0; j-- {
			blockPos := blockLength - j
			//fmt.Printf("  Byte: %d\n", j)
			prefix := bytes.Repeat([]byte("a"), j-1)
			currDict := makeDict(prefix, decrypted)
			//fmt.Printf("%v -> %v\n", append(prefix, decrypted[i:i+blockPos]...), oracle(prefix)[i:i+blockLength])
			corrByte := currDict[string(oracle(prefix)[i:i+blockLength])]
			decrypted = append(decrypted, corrByte)
			if blockPos+i >= ciphertextLen {
				break
			}
		}

	}

	return decrypted

}

func ValidatePKCS7(padded []byte) error {
	padByte := padded[len(padded)-1]
	for i := len(padded) - 1; i > len(padded)-int(padByte)-1; i-- {
		if padded[i] != padByte {
			return fmt.Errorf("%v is not PKCS #7 padded", padded)
		}
	}
	return nil
}

func MakeBitflippingOracle() (
	encryptString func(string) []byte,
	checkAdmin func([]byte) bool) {
	key := RandomAESKey()
	semiRE := regexp.MustCompile(";")
	eqRE := regexp.MustCompile("=")
	encryptString = func(in string) []byte {
		in = semiRE.ReplaceAllLiteralString(in, "\";\"")
		in = eqRE.ReplaceAllLiteralString(in, "\"=\"")
		toEncrypt := "comment1=cooking%20MCs;userdata=" +
			in +
			";comment2=%20like%20a%20pound%20of%20bacon"
		return EncryptECB([]byte(toEncrypt), key)
	}
	checkAdmin = func(in []byte) bool {
		decrypted := string(UnpadPKCS7(DecryptECB(in, key)))
		return strings.Contains(decrypted, ";admin=true;")

	}

}
