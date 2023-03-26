package test

import (
	"Image-Encryption-Using-Triple-DES-GO/internal"
	"Image-Encryption-Using-Triple-DES-GO/pkg"
	"bytes"
	"testing"
)

func TestDESEncryptionDecryption(t *testing.T) {
	key := []byte("12345678")
	plaintext, _ := image.ReadImage("../pkg/testdata/Genshin-Impact.jpg")

	// 加密
	ciphertext, err := internal.DesEncryption(plaintext, key)
	if err != nil {
		t.Fatalf("加密过程中发生错误: %v", err)
	}

	// 解密
	result, err := internal.DesDecryption(ciphertext, key)
	if err != nil {
		t.Fatalf("解密过程中发生错误: %v", err)
	}

	// 检查结果是否正确
	if !bytes.Equal(result, plaintext) {
		t.Errorf("解密后的结果与原始明文不一致: got %v, want %v", result, plaintext)
	}
}
