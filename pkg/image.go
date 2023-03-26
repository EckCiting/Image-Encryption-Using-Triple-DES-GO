package image

import (
	"bytes"
	"crypto/des"
	"io"
	"os"
)

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...) // 将 padText 切片中的元素逐个展开，作为函数 append 的可变参数传入。
}

func ReadImage(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close() // defer语句在函数返回前关闭文件句柄

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	blockSize := des.BlockSize
	data = pkcs7Pad(data, blockSize)

	return data, nil // error is nil
}
