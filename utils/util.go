package utils

import (
	"fmt"
	"log"
)

func Usage() {
	fmt.Println("Generating HD wallet key pair")
	fmt.Println("-p : 	Input passphrase")
}

func HandleError(err error) {
	if err != nil {
		log.Panic("Error : ", err)
	}
}
