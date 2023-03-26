package main

import (
	"Image-Encryption-Using-Triple-DES-GO/internal"
	"Image-Encryption-Using-Triple-DES-GO/pkg"
	"fmt"
)

func main() {
	fmt.Println("hello world!")
	fmt.Println(descore.Test())

	var data, _ = image.ReadImage("pkg/testdata/Genshin_Impact.jpg")
	fmt.Println(data)

}
