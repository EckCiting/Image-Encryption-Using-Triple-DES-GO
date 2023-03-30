package internal

import (
	"fmt"
	"strconv"
	"strings"
)

const ENCRYPT_MODE int = 0
const DECRYPT_MODE int = 1

var IP_table [64]int = [64]int{
	58, 50, 42, 34, 26, 18, 10, 2,
	60, 52, 44, 36, 28, 20, 12, 4,
	62, 54, 46, 38, 30, 22, 14, 6,
	64, 56, 48, 40, 32, 24, 16, 8,
	57, 49, 41, 33, 25, 17, 9, 1,
	59, 51, 43, 35, 27, 19, 11, 3,
	61, 53, 45, 37, 29, 21, 13, 5,
	63, 55, 47, 39, 31, 23, 15, 7,
}

var IP_table_reverse = [64]int{
	40, 8, 48, 16, 56, 24, 64, 32,
	39, 7, 47, 15, 55, 23, 63, 31,
	38, 6, 46, 14, 54, 22, 62, 30,
	37, 5, 45, 13, 53, 21, 61, 29,
	36, 4, 44, 12, 52, 20, 60, 28,
	35, 3, 43, 11, 51, 19, 59, 27,
	34, 2, 42, 10, 50, 18, 58, 26,
	33, 1, 41, 9, 49, 17, 57, 25,
}

var E_table = [48]int{
	32, 1, 2, 3, 4, 5,
	4, 5, 6, 7, 8, 9,
	8, 9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32, 1,
}

var P_table = [48]int{
	16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25,
}

var S_boxes = [][][]int{
	{
		{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
		{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
		{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
		{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13},
	},
	{
		{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
		{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
		{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
		{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9},
	},
	{
		{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
		{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
		{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
		{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12},
	},
	{
		{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
		{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
		{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
		{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14},
	},
	{
		{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
		{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
		{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
		{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3},
	},
	{
		{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
		{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
		{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
		{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13},
	},
	{
		{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
		{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
		{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
		{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12},
	},
	{
		{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
		{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
		{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
		{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11},
	},
}

var drop_table = []int{
	57, 49, 41, 33, 25, 17, 9,
	1, 58, 50, 42, 34, 26, 18,
	10, 2, 59, 51, 43, 35, 27,
	19, 11, 3, 60, 52, 44, 36,
	63, 55, 47, 39, 31, 23, 15,
	7, 62, 54, 46, 38, 30, 22,
	14, 6, 61, 53, 45, 37, 29,
	21, 13, 5, 28, 20, 12, 4,
}

var compression_table = []int{
	14, 17, 11, 24, 1, 5,
	3, 28, 15, 6, 21, 10,
	23, 19, 12, 4, 26, 8,
	16, 7, 27, 20, 13, 2,
	41, 52, 31, 37, 47, 55,
	30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53,
	46, 42, 50, 36, 29, 32,
}

var shift_table = []int{1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1}

/*
 * Convert 8 bytes (64 bits) to String
 */
func ByteToString(bytes []byte) string {
	binaryStrings := ""
	for _, v := range bytes {
		binaryStrings += fmt.Sprintf("%08b", v)
	}
	return binaryStrings
}

/*
 * Convert 64 length String to 8 bytes (64 bits)
 */

func StringToBytes(s string) []byte {
	var t []byte
	for i := 0; i < len(s); i += 8 {
		if i+8 > len(s) {
			break
		}
		subs := s[i : i+8]
		val, _ := strconv.ParseUint(subs, 2, 8)
		t = append(t, byte(val))
	}
	return t
}

func Cipher(bytes, originalKey []byte, keyType int) []byte {
	var res []byte
	for i := 0; i < len(bytes)/8; i++ {
		block := bytes[i*8 : i*8+8]
		tmp := DESBlockOperation(block, originalKey, keyType)
		res = append(res, tmp...)
	}
	return res
}

func generateSubKeys(originalKey []byte) []string {
	// convert to binary
	keyBinary := ByteToString(originalKey)

	// Parity drop
	keyBinaryPart := strings.Builder{}
	for i := 0; i < 56; i++ {
		keyBinaryPart.WriteByte(keyBinary[drop_table[i]-1])
	}

	// 16 iterations
	subKeys := make([]string, 16)
	C0 := keyBinaryPart.String()[:28]
	D0 := keyBinaryPart.String()[28:]
	for i := 0; i < 16; i++ {
		// shift left
		C0 = C0[shift_table[i]:] + C0[:shift_table[i]]
		D0 = D0[shift_table[i]:] + D0[:shift_table[i]]
		C0D0 := C0 + D0

		// Compression D-box
		subKey := strings.Builder{}
		for j := 0; j < 48; j++ {
			subKey.WriteByte(C0D0[compression_table[j]-1])
		}
		subKeys[i] = subKey.String()
	}

	return subKeys
}

func Xor(s1, s2 string) string {
	var res string
	for i := 0; i < len(s1); i++ {
		if s1[i] == s2[i] {
			res += "0"
		} else {
			res += "1"
		}
	}
	return res
}

func DESBlockOperation(plaintext []byte, originalKey []byte, types int) []byte {

	// 这里是将 bytes 转换成 01 字符串
	// 而且string是不可变的，所以用了一些rune
	// 我知道这样写很奇怪，等有空再改吧

	// convert to binary string
	plaintextBinaryString := ByteToString(plaintext)

	// Initial permutation
	substitutePlaintext := strings.Builder{}
	for i := 0; i < 64; i++ {
		substitutePlaintext.WriteByte(plaintextBinaryString[IP_table[i]-1])
	}
	//fmt.Println(substitutePlaintext.String()) // Pass

	// Split into 32-bit Left and Right part
	L := substitutePlaintext.String()[:32]
	R := substitutePlaintext.String()[32:]

	//fmt.Println(L, R) //Pass

	// generate keys
	subKeys := generateSubKeys(originalKey)
	if types == DECRYPT_MODE {
		subKeyTmp := generateSubKeys(originalKey)
		for i := 0; i < 16; i++ {
			subKeys[i] = subKeyTmp[15-i]
		}
	}

	//for _, subkey := range subKeys {
	//	fmt.Println(subkey)
	//} // Pass

	// 16 rounds operation
	for i := 0; i < 16; i++ {
		// Expand D-box (E permutation)
		Rtmp := make([]byte, 48)
		for j := 0; j < 48; j++ {
			Rtmp[j] = R[E_table[j]-1]
		}
		//fmt.Println(string(Rtmp)) // pass
		// xor
		Rtmp = []byte((Xor(string(Rtmp), subKeys[i])))
		//fmt.Println(string(Rtmp)) // pass

		// S-Box compression
		Rtmp2 := strings.Builder{}
		for j := 0; j < 8; j++ {
			// each 6-bit unit
			unit := string(Rtmp[j*6 : j*6+6])

			row, _ := strconv.ParseInt(string(unit[0])+string(unit[5]), 2, 8)
			col, _ := strconv.ParseInt(string(unit[1:5]), 2, 8)
			val := S_boxes[j][row][col]
			Rtmp2.WriteString(fmt.Sprintf("%04b", val))
		}
		//fmt.Println(R) // pass
		// P-box permutation
		Rtmp = make([]byte, 32)
		for j := 0; j < 32; j++ {
			Rtmp[j] = Rtmp2.String()[P_table[j]-1]
		}
		//fmt.Println(string(Rtmp)) // pass

		// swap in 15 rounds
		if i != 15 {
			L, R = R, Xor(L, string(Rtmp))
		} else {
			L = Xor(L, string(Rtmp))
		}
		//fmt.Printf("L%d: %s\n", i+1, L)
		//fmt.Printf("R%d: %s\n", i+1, R) // pass
	}
	LR := L + R
	// Final permutation
	ciphertext := strings.Builder{}
	for i := 0; i < 64; i++ {
		ciphertext.WriteByte(LR[IP_table_reverse[i]-1])
	}
	return StringToBytes(ciphertext.String())
}
