package main

import (
	"Image-Encryption-Using-Triple-DES-GO/web/router"
)

func main() {

	//r := gin.Default()
	r := router.SetupRouter()
	r.Run() // listen and serve on 0.0.0.0:8080

}
