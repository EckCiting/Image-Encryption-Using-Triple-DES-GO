package test

import (
	"Image-Encryption-Using-Triple-DES-GO/internal"
	"bytes"
	"testing"
)

func TestMakeKey(t *testing.T) {
	password := []byte("myPassword123")
	salt1 := []byte("salt1")
	salt2 := []byte("salt2")

	expectedKeyLength := 24

	key := internal.MakeKey(password, salt1, salt2)

	if len(key) != expectedKeyLength {
		t.Errorf("unexpected key length: got %d, want %d", len(key), expectedKeyLength)
	}

	// verify that two different keys are generated for different salts
	key1 := internal.MakeKey(password, []byte("differentSalt1"), salt2)
	key2 := internal.MakeKey(password, []byte("differentSalt2"), salt2)
	key3 := internal.MakeKey(password, []byte("differentSalt1"), salt2)

	if bytes.Equal(key1, key2) {
		t.Errorf("keys generated for different salts are equal")
	}

	if !bytes.Equal(key1, key3) {
		t.Errorf("keys generated for same salts are not equal")
	}

}
