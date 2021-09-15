package server

import (
	"github.com/Wee-code-Golang-Dojo/todo-manager/handlers"
	"github.com/gin-gonic/gin"
)

func Run(port string) error {
	// create a new gin router
	router := gin.Default()

	// define a single endpoint
	router.GET("/", handlers.WelcomeHandler)

	// CRUD enpoints for data

	// create
	router.POST("/createTask", handlers.CreateTaskHandler)

	// retrieve
	router.GET("/getTask/:id", handlers.GetSingleTaskHandler)

	router.GET("/getUsers", handlers.GetAllUserHandler)

	router.GET("/getTasks", handlers.GetAllTasksHandler)

	// update
	router.PATCH("/updateTask/:id", handlers.UpdateTaskHandler)

	// delete
	router.DELETE("/deleteTask/:name", handlers.DeleteTaskHandler)

	router.POST("/login", handlers.LoginHandler)

	router.POST("/signup", handlers.SignupHandler)

	err := router.Run(":" + port)

	if err != nil {
		return err
	}

	return nil
}
