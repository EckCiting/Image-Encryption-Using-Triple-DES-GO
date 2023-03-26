package internal

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func DesEncryption(data []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error in creating cipher: %v", err)
	}

	ciphertext := make([]byte, len(data))
	blockMode := cipher.NewCBCEncrypter(block, key)
	blockMode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}

func DesDecryption(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error in creating cipher: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))
	blockMode := cipher.NewCBCDecrypter(block, key)
	blockMode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}
