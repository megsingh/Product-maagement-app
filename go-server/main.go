package main

import (
	"fmt"
	"net/http"

	"go-server/router"
)

func main() {
	r := router.Router()
	fmt.Println("Starting server on the port 5000...")
	http.ListenAndServe(":5000", r)
}
