package controller

import (
	"fmt"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
)

type ImageController struct{}

func (ic *ImageController) UploadImage(c *gin.Context) {
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bad Request"})
		return
	}

	fmt.Println(body)

	c.JSON(200, gin.H{
		"message": "success",
	})
}
