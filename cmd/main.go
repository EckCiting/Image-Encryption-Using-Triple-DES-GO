package main

import (
	"Image-Encryption-Using-Triple-DES-GO/web/models"
	"Image-Encryption-Using-Triple-DES-GO/web/router"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func main() {

	db, err := gorm.Open(sqlite.Open("test.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	// Auto Migrate
	err = db.AutoMigrate(&models.Image{})
	if err != nil {
		panic("failed to migrate models")
	}

	//r := gin.Default()
	r := router.SetupRouter()
	r.Run() // listen and serve on 0.0.0.0:8080

}
