package pkg

import (
	"Image-Encryption-Using-Triple-DES-GO/web/models"
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

func CleanExpSalt() {
	now := time.Now().UTC()

	var images []models.Image
	DB.Where("expire_date < ?", now).Find(&images)
	for _, image := range images {
		image.Salt = ""
		DB.Save(&image)
	}
}

// StartCleanExpSaltTicker 每小时调用一次 CleanExpSalt
func StartCleanExpSaltTicker() {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	for {
		select { // 阻塞 goroutine
		case <-ticker.C: // C表示一个channel,ticker.C 会周期性地向 channel 发送一个时间点的值，表示当前时间到达了一个周期
			CleanExpSalt()
		}
	}
}
