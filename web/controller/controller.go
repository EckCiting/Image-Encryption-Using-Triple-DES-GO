package controller

import (
	"Image-Encryption-Using-Triple-DES-GO/internal"
	image "Image-Encryption-Using-Triple-DES-GO/pkg"
	"bytes"
	"crypto/des"
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ImageController struct{}

func (ic *ImageController) EncryptImage(c *gin.Context) {
	file, err := c.FormFile("image")
	password := c.PostForm("password")
	if err != nil {
		fmt.Printf("failed to do something: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	f, err := file.Open()
	if err != nil {

	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {

	}

	blockSize := des.BlockSize
	fileContent := image.Pkcs7Pad(buf.Bytes(), blockSize)

	//TODO: generate random salt and iv
	salt1 := []byte("00000000")
	salt2 := []byte("00000000")
	iv := []byte("00000000")

	keys := internal.MakeKey([]byte(password), salt1, salt2)

	data, err := internal.TDESEncryption(fileContent, keys, iv)
	if err != nil {
		return
	}

	filename := file.Filename
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Writer.Write(data)
}

func (ic *ImageController) DecryptImage(c *gin.Context) {
	file, err := c.FormFile("image")
	password := c.PostForm("password")
	if err != nil {
		fmt.Printf("failed to do something: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	f, err := file.Open()
	if err != nil {

	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {

	}

	blockSize := des.BlockSize
	fileContent := image.Pkcs7Pad(buf.Bytes(), blockSize)

	//TODO: get salt and iv from database
	salt1 := []byte("00000000")
	salt2 := []byte("00000000")
	iv := []byte("00000000")

	keys := internal.MakeKey([]byte(password), salt1, salt2)

	data, err := internal.TDESDecryption(fileContent, keys, iv)
	if err != nil {
		return
	}

	filename := file.Filename
	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
	c.Writer.Write(data)
}
