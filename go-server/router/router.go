package router

import (
	"go-server/middleware"

	"github.com/gorilla/mux"
)

func Router() *mux.Router {

	router := mux.NewRouter()

	router.HandleFunc("/api/products", middleware.IsAuthorized(middleware.GetProducts)).Methods("GET", "OPTIONS")
	router.HandleFunc("/api/products/add", middleware.IsAuthorized(middleware.AddProduct)).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/products/edit/{id}", middleware.IsAuthorized(middleware.UpdateProduct)).Methods("PUT", "OPTIONS")
	router.HandleFunc("/api/products/delete/{id}", middleware.IsAuthorized(middleware.DeleteProduct)).Methods("DELETE", "OPTIONS")
	router.HandleFunc("/api/user/login", middleware.UserLogin).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/user/register", middleware.UserRegister).Methods("POST", "OPTIONS")
	return router
}
