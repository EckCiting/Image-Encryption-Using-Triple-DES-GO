package router

import (
	"Image-Encryption-Using-Triple-DES-GO/web/controller"
	"github.com/gin-gonic/gin"
)

func SetupRouter() *gin.Engine {
	r := gin.Default()

	imageCtrl := &controller.ImageController{}
	r.POST("/encryptImage", imageCtrl.EncryptImage)
	r.POST("/decryptImage", imageCtrl.DecryptImage)

	return r
}
