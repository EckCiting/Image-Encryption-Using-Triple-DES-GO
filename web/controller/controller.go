package controller

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ImageController struct{}

func (ic *ImageController) UploadImage(c *gin.Context) {
	file, err := c.FormFile("image")
	if err != nil {
		fmt.Printf("failed to do something: %v\n", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	fmt.Println(file)

	c.JSON(200, gin.H{
		"message": "success",
	})
}
