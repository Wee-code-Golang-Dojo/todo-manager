package main

import (
	"log"
	"os"

	"github.com/Wee-code-Golang-Dojo/todo-manager/server"
)

func main() {
	// run the server on the port 3000
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}

	err := server.Run(port)
	if err != nil {
		log.Fatal("Could not start server")
	}
}
