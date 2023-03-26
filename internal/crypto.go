package internal

import (
	"crypto/cipher"
	"crypto/des"
	"fmt"
)

func DesEncryption(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error in creating cipher: %v", err)
	}

	ciphertext := make([]byte, len(data))
	blockMode := cipher.NewCBCEncrypter(block, iv)
	blockMode.CryptBlocks(ciphertext, data)

	return ciphertext, nil
}

func DesDecryption(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("error in creating cipher: %v", err)
	}

	plaintext := make([]byte, len(ciphertext))
	blockMode := cipher.NewCBCDecrypter(block, iv)
	blockMode.CryptBlocks(plaintext, ciphertext)

	return plaintext, nil
}

func TDESEncryption(data []byte, keys []byte, iv []byte) ([]byte, error) {
	k1 := keys[:8]
	encrypted1, err := DesEncryption(data, k1, iv)
	if err != nil {
		panic(err)
	}

	k2 := keys[8:16]
	decrypted2, err := DesDecryption(encrypted1, k2, iv)
	if err != nil {
		panic(err)
	}

	k3 := keys[16:]
	encrypted3, err := DesEncryption(decrypted2, k3, iv)
	if err != nil {
		panic(err)
	}

	return encrypted3, err
}

func TDESDecryption(data []byte, keys []byte, iv []byte) ([]byte, error) {

	k3 := keys[16:]
	decrypted3, err := DesDecryption(data, k3, iv)
	if err != nil {
		panic(err)
	}

	k2 := keys[8:16]
	encrypted2, err := DesEncryption(decrypted3, k2, iv)
	if err != nil {
		panic(err)
	}

	k1 := keys[:8]
	decrypted1, err := DesDecryption(encrypted2, k1, iv)
	if err != nil {
		panic(err)
	}

	return decrypted1, err
}
