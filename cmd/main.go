package main

import (
	"Image-Encryption-Using-Triple-DES-GO/pkg"
	"Image-Encryption-Using-Triple-DES-GO/web/router"
	"fmt"
)

func main() {

	err := pkg.CreatDB()
	if err != nil {
		fmt.Printf("failed to start database: %v\n", err)
		return
	}

	go pkg.StartCleanExpSaltTicker()
	//r := gin.Default()
	r := router.SetupRouter()
	err = r.Run()
	if err != nil {
		return
	} // listen and serve on 0.0.0.0:8080

}
