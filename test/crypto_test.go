package test

import (
	"Image-Encryption-Using-Triple-DES-GO/internal"
	"Image-Encryption-Using-Triple-DES-GO/pkg"
	"bytes"
	"crypto/des"
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDESEncryptionDecryption(t *testing.T) {
	key := []byte("12345678")
	plaintext, err := pkg.ReadImage("../pkg/testdata/Genshin_Impact.jpg")
	if err != nil {
		t.Fatalf("读取文件发生错误: %v", err)
	}
	iv := []byte("00000000")

	// 加密
	ciphertext, err := internal.DesEncryption(plaintext, key, iv)
	if err != nil {
		t.Fatalf("加密过程中发生错误: %v", err)
	}

	// 解密
	result, err := internal.DesDecryption(ciphertext, key, iv)
	if err != nil {
		t.Fatalf("解密过程中发生错误: %v", err)
	}

	// 检查结果是否正确
	if !bytes.Equal(result, plaintext) {
		t.Errorf("解密后的结果与原始明文不一致: got %v, want %v", result, plaintext)
	}
}

func TestTDESEncryptionDecryption(t *testing.T) {
	keys := []byte("123456789012345678901234")
	plaintext, err := pkg.ReadImage("../pkg/testdata/Genshin_Impact.jpg")
	if err != nil {
		t.Fatalf("读取文件发生错误: %v", err)
	}
	iv := []byte("00000000")

	// 加密
	ciphertext, err := internal.TDESEncryption(plaintext, keys, iv)
	if err != nil {
		t.Fatalf("加密过程中发生错误: %v", err)
	}

	// 解密
	result, err := internal.TDESDecryption(ciphertext, keys, iv)
	if err != nil {
		t.Fatalf("解密过程中发生错误: %v", err)
	}

	// 检查结果是否正确
	if !bytes.Equal(result, plaintext) {
		t.Errorf("解密后的结果与原始明文不一致: got %v, want %v", result, plaintext)
	}
}

func TestStringToBytes(t *testing.T) {
	s := "000000010000001000000011"
	expected := []byte{1, 2, 3}
	result := internal.StringToBytes(s)

	if !reflect.DeepEqual(expected, result) {
		t.Errorf("Expected %v, but got %v", expected, result)
	}
}

func TestBytesToString(t *testing.T) {
	b := []byte{1, 2, 3}
	expected := "000000010000001000000011"
	result := internal.ByteToString(b)

	if expected != result {
		t.Errorf("Expected %s, but got %s", expected, result)
	}
}

func TestXOR(t *testing.T) {
	// Test case 1: Both inputs are same
	input1 := "01010101"
	input2 := "01010101"
	expectedOutput := "00000000"
	if output := internal.Xor(input1, input2); output != expectedOutput {
		t.Errorf("Expected %s, but got %s", expectedOutput, output)
	}

	// Test case 2: Inputs are different
	input1 = "01010101"
	input2 = "00110011"
	expectedOutput = "01100110"
	if output := internal.Xor(input1, input2); output != expectedOutput {
		t.Errorf("Expected %s, but got %s", expectedOutput, output)
	}

}

func TestCipherEncrypt(t *testing.T) {
	key := []byte("12345678")
	plaintext := []byte("TESTTEST")
	expectedCiphertext := "82ae19e37cc123bc"

	// Encrypt using manual implementation
	ciphertext := internal.Cipher(plaintext, key, internal.ENCRYPT_MODE)
	if hex.EncodeToString(ciphertext) != expectedCiphertext {
		t.Errorf("Manual implementation encryption failed, expected %s but got %s", expectedCiphertext, hex.EncodeToString(ciphertext))
	}

	// Encrypt using crypto/des library
	block, _ := des.NewCipher(key)
	encrypted := make([]byte, len(plaintext))
	block.Encrypt(encrypted, plaintext)
	if hex.EncodeToString(encrypted) != expectedCiphertext {
		t.Errorf("Crypto/des encryption failed, expected %s but got %s", expectedCiphertext, hex.EncodeToString(encrypted))
	}

	// Compare results
	if !reflect.DeepEqual(ciphertext, encrypted) {
		t.Errorf("Encryption results not equal, manual implementation: %v, crypto/des: %v", ciphertext, encrypted)
	}
}

func TestCipherDecrypt(t *testing.T) {
	key := []byte("12345678")
	ciphertext, _ := hex.DecodeString("82ae19e37cc123bc")
	expectedPlaintext := "TESTTEST"

	// Decrypt using manual implementation
	plaintext := internal.Cipher(ciphertext, key, internal.DECRYPT_MODE)
	if string(plaintext) != expectedPlaintext {
		t.Errorf("Manual implementation decryption failed, expected %s but got %s", expectedPlaintext, string(plaintext))
	}

	// Decrypt using crypto/des library
	block, _ := des.NewCipher(key)
	decrypted := make([]byte, len(ciphertext))
	block.Decrypt(decrypted, ciphertext)
	if string(decrypted) != expectedPlaintext {
		t.Errorf("Crypto/des decryption failed, expected %s but got %s", expectedPlaintext, string(decrypted))
	}

	// Compare results
	if !reflect.DeepEqual(plaintext, decrypted) {
		t.Errorf("Decryption results not equal, manual implementation: %v, crypto/des: %v", plaintext, decrypted)
	}
}

func TestManualDES(t *testing.T) {
	plaintext := internal.StringToBytes("0011000000110001001100100011001100110100001101010011011000110111") // 01234567
	key := internal.StringToBytes("0011000100110010001100110011010000110101001101100011011100111000")       // 12345678
	ciphertext := internal.Cipher(plaintext, key, internal.ENCRYPT_MODE)
	decrypttext := internal.Cipher(ciphertext, key, internal.DECRYPT_MODE)
	if !reflect.DeepEqual(plaintext, decrypttext) {
		t.Errorf("Expected %v and %v not equal", plaintext, decrypttext)
	}
}
