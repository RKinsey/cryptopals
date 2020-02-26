package cryptopals

func PadPKCS7(plaintext []byte, blocksize int) []byte {
	if len(plaintext)%blocksize == 0 {
		return plaintext
	}
	padlen := byte(blocksize - len(plaintext)%blocksize)
	padding := make([]byte, padlen)
	for i := range padding {
		padding[i] = padlen
	}
	return append(plaintext, padding...)
}
