package controller

import (
	"Image-Encryption-Using-Triple-DES-GO/internal"
	"Image-Encryption-Using-Triple-DES-GO/pkg"
	"Image-Encryption-Using-Triple-DES-GO/web/models"
	"bytes"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

type ImageController struct{}

func (ic *ImageController) EncryptImage(c *gin.Context) {
	file, err := c.FormFile("image")
	password := c.PostForm("password")
	exptime, err := time.Parse("2006-01-02T15:04:05", c.PostForm("exptime"))
	if err != nil {
		fmt.Printf("expDate format error: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}
	pkg.CleanExpSalt()

	// Read image in the form
	f, err := file.Open()
	if err != nil {

	}
	defer f.Close()
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {

	}

	filename := file.Filename
	blockSize := des.BlockSize
	fileContent := pkg.Pkcs7Pad(buf.Bytes(), blockSize)

	// Generate random salt and iv
	salt := make([]byte, 16)
	iv := make([]byte, 8)
	_, err = rand.Read(salt)
	if err != nil {
		return
	}
	_, err = rand.Read(iv)
	if err != nil {
		return
	}
	salt1 := salt[:8]
	salt2 := salt[8:]

	// generate key and encrypt
	keys := internal.MakeKey([]byte(password), salt1, salt2)
	data, err := internal.TDESEncryption(fileContent, keys, iv)
	if err != nil {
		return
	}

	// store to database
	err = pkg.StoreImageToDB(filename, pkg.CalculateMD5Hash(data), exptime, salt, iv)
	if err != nil {
		fmt.Printf("failed to store to database: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	c.Header("Content-Type", "application/octet-stream")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", "enc_"+filename))
	c.Writer.Write(data)
}

func (ic *ImageController) DecryptImage(c *gin.Context) {
	file, err := c.FormFile("image")
	password := c.PostForm("password")
	if err != nil {
		fmt.Printf("failed to decrypt: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	pkg.CleanExpSalt()
	f, err := file.Open()
	if err != nil {

	}
	defer f.Close()

	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, f); err != nil {

	}

	//blockSize := des.BlockSize
	//fileContent := pkg.Pkcs7Pad(buf.Bytes(), blockSize)

	fileContent := buf.Bytes()
	filehash := pkg.CalculateMD5Hash(fileContent)
	// find image info according to filehash
	var image models.Image
	result := pkg.DB.Where("image_hash = ?", filehash).First(&image)

	if result.Error != nil {
		// 处理查询出错的情况
	}
	if result.RowsAffected == 0 {
		// 未找到对应记录
	} else {
		saltString := image.Salt
		salt, err := hex.DecodeString(saltString)
		if err != nil {
			panic(err)
		}
		if len(saltString) == 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
			return
		}
		salt1 := salt[:8]
		salt2 := salt[8:]

		ivString := image.IV
		iv, err := hex.DecodeString(ivString)
		if err != nil {
			panic(err)
		}
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
}
