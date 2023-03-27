package internal

import (
	"crypto/sha512"
	"encoding/hex"
	"golang.org/x/crypto/pbkdf2"
)

func slowHash(password []byte, salt []byte, iterations int, keyLength int) []byte {
	skf := sha512.New
	key := pbkdf2.Key([]byte(password), salt, iterations, keyLength, skf)
	return key
}

func MakeKey(password []byte, salt1 []byte, salt2 []byte) []byte {
	iterations := 100000
	keyLength := 24

	/*
	 *  salt1, salt2 = salt.split()
	 *  hashvalue1 = SlowHash(password + salt1)
	 *  hashvalue2 = SlowHash(hashvalue1 + salt2)
	 */

	hashValue1 := slowHash(password, salt1, iterations, keyLength)
	hashValueString1 := hex.EncodeToString(hashValue1)
	hashValueChars1 := []byte(hashValueString1)
	hashValue2 := slowHash(hashValueChars1, salt2, iterations, keyLength)

	return hashValue2
}
