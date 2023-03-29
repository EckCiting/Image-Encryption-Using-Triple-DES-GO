package pkg

import (
	"Image-Encryption-Using-Triple-DES-GO/web/models"
	"crypto/md5"
	"encoding/hex"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"time"
)

var DB *gorm.DB // package level variable

func CreatDB() error {
	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// Auto Migrate
	err = db.AutoMigrate(&models.Image{})
	if err != nil {
		panic("failed to migrate models")
	}
	DB = db
	return nil
}

func StoreImageToDB(filename string, filehash string, exptime time.Time, salts []byte, iv []byte) error {
	image := models.Image{
		ImageName:  filename,
		ImageHash:  filehash,
		ExpireDate: exptime,
		Salt:       hex.EncodeToString(salts),
		IV:         hex.EncodeToString(iv),
	}
	result := DB.Create(&image)
	if result.Error != nil {
		return result.Error
	}
	return nil
}

func CalculateMD5Hash(fileContent []byte) string {
	h := md5.New()
	h.Write(fileContent)
	return hex.EncodeToString(h.Sum(nil))
}
