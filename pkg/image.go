package image

import (
	"io"
	"os"
)

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

	return data, nil // error is nil
}
