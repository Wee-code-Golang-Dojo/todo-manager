package handlers

import (
	"fmt"
	"strings"
	"time"

	"github.com/Wee-code-Golang-Dojo/todo-manager/db"
	"github.com/Wee-code-Golang-Dojo/todo-manager/lib/jawt"
	"github.com/Wee-code-Golang-Dojo/todo-manager/models"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtSecret = "secretname"
)

func WelcomeHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"message": "welcome to task manager API",
	})
}

func CreateTaskHandler(c *gin.Context) {
	// create task for a specific user
	//  we need to find out the identity of the user
	//  this endpoint does not request for the users details like email or user id
	// as you've already gotten the details during login
	//  the request only contains the task and the jwt token

	//  the jwt token is what we use to identify the user
	// we generate this token during login or signup
	// because it is at that point that we confirm things like password and other security details we might be intersted in
	// you can't be asking the user for password at every endpoint
	// the jwt only contains the things we put inside
	// the only thing we need for our app to identify the user is the users id

	// for http request, the standard way the jwt is usually sent is as a request header
	// we need to get jwt token from request header using then key
	// for the jwt the key name is "Authorization"
	authorization := c.Request.Header.Get("Authorization")

	//  we return an error to the user if the token was not supplied
	if authorization == "" {
		c.JSON(401, gin.H{
			"error": "auth token not supplied",
		})
		return
	}

	jwtToken := ""

	// split the authenthication token which looks like "Bearer asdsadsdsdsdsa........."
	//  so that we can get the second part of the string which is the actual jwt token
	splitTokenArray := strings.Split(authorization, " ")
	if len(splitTokenArray) > 1 {
		jwtToken = splitTokenArray[1]
	}

	claims, err := jawt.ValidateToken(jwtToken)
	if err != nil {
		c.JSON(401, gin.H{
			"error": "invalid jwt token",
		})
		return
	}

	// now that we have validated the token and we've been able to get the users identity
	// we can continue the request

	// create an empty task object to get the request body
	var taskReq models.Task

	err = c.ShouldBindJSON(&taskReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	// generate task id
	taskId := uuid.NewV4().String()

	task := models.Task{
		ID:          taskId,
		Owner:       claims.UserId,
		Name:        taskReq.Name,
		Description: taskReq.Description,
		Ts:          time.Now(),
	}

	_, err = db.CreateTask(&task)
	if err != nil {
		fmt.Println("error saving task", err)
		c.JSON(500, gin.H{
			"error": "Could not process request, could not save task",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "succesfully created task",
		"data":    task,
	})
}

func GetSingleTaskHandler(c *gin.Context) {
	taskId := c.Param("id")

	task, err := db.GetSingleTask(taskId)
	if err != nil {
		fmt.Println("user not found", err)
		c.JSON(404, gin.H{
			"error": "invalid task id: " + taskId,
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
		"data":    task,
	})
}

func GetAllUserHandler(c *gin.Context) {
	users, err := db.GetAllUsers()
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could get users",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
		"data":    users,
	})
}

func GetAllTasksHandler(c *gin.Context) {
	// get jwt token from request
	authorization := c.Request.Header.Get("Authorization")
	if authorization == "" {
		c.JSON(401, gin.H{
			"error": "auth token required",
		})
		return
	}

	jwtToken := ""
	sp := strings.Split(authorization, " ")
	if len(sp) > 1 {
		jwtToken = sp[1]
	}

	// decode token to get claims
	claims := &models.Claims{}
	keyFunc := func(token *jwt.Token) (i interface{}, e error) {
		return []byte(jwtSecret), nil
	}

	token, err := jwt.ParseWithClaims(jwtToken, claims, keyFunc)
	if !token.Valid {
		c.JSON(401, gin.H{
			"error": "invalid jwt token",
		})
		return
	}

	// edit to get only tasks for a specific user
	tasks, err := db.GetAllTasks(claims.UserId)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could get tasks",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "success",
		"data":    tasks,
	})
}

func UpdateTaskHandler(c *gin.Context) {
	// get the value passed from the client
	taskId := c.Param("id")

	// creating an empty object to store request data
	var task models.Task

	// gets the user data that was sent from the client
	// fills up our empty user object with the sent data
	err := c.ShouldBindJSON(&task)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	err = db.UpdateTask(taskId, task.Name, task.Description)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could not update task",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "Task updated!",
	})
}

func DeleteTaskHandler(c *gin.Context) {
	authorization := c.Request.Header.Get("Authorization")

	//  we return an error to the user if the token was not supplied
	if authorization == "" {
		c.JSON(401, gin.H{
			"error": "auth token not supplied",
		})
		return
	}

	jwtToken := ""

	// split the authenthication token which looks like "Bearer asdsadsdsdsdsa........."
	//  so that we can get the second part of the string which is the actual jwt token
	splitTokenArray := strings.Split(authorization, " ")
	if len(splitTokenArray) > 1 {
		jwtToken = splitTokenArray[1]
	}

	claims, err := jawt.ValidateToken(jwtToken)
	if err != nil {
		c.JSON(401, gin.H{
			"error": "invalid jwt token",
		})
		return
	}

	// get the value passed from the client
	taskId := c.Param("id")

	err = db.DeleteTask(taskId, claims.UserId)
	if err != nil {
		c.JSON(500, gin.H{
			"error": "Could not process request, could not delete task",
		})
		return
	}

	c.JSON(200, gin.H{
		"message": "Task deleted!",
	})
}

func LoginHandler(c *gin.Context) {
	loginReq := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{}

	err := c.ShouldBindJSON(&loginReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	user, err := db.GetUserByEmail(loginReq.Email)
	if err != nil {
		fmt.Printf("error gettinng user from db: %v\n", err)
		c.JSON(500, gin.H{
			"error": "Could not process request, could get user",
		})
		return
	}

	// if found compare password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginReq.Password))
	if err != nil {
		fmt.Printf("error validating password: %v\n", err)
		c.JSON(500, gin.H{
			"error": "Invalid login details",
		})
		return
	}

	jwtTokenString, err := jawt.CreateToken(user.ID)

	c.JSON(200, gin.H{
		"message": "sign up successful",
		"token":   jwtTokenString,
		"data":    user,
	})
}

func SignupHandler(c *gin.Context) {
	type SignupRequest struct {
		Name     string `json:"name"`
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	var signupReq SignupRequest

	err := c.ShouldBindJSON(&signupReq)
	if err != nil {
		c.JSON(400, gin.H{
			"error": "invalid request data",
		})
		return
	}

	exists := db.CheckUserExists(signupReq.Email)
	if exists {
		c.JSON(500, gin.H{
			"error": "Email already exits, please use a different email",
		})
		return
	}

	bytes, err := bcrypt.GenerateFromPassword([]byte(signupReq.Password), bcrypt.DefaultCost)
	hashPassword := string(bytes)

	// generate user id
	userId := uuid.NewV4().String()

	user := models.User{
		ID:       userId,
		Name:     signupReq.Name,
		Email:    signupReq.Email,
		Password: hashPassword,
		Ts:       time.Now(),
	}

	// store the users data
	_, err = db.CreateUser(&user)
	if err != nil {
		fmt.Println("error saving user", err)
		//	if saving ws not successful
		c.JSON(500, gin.H{
			"error": "Could not process request, could not save user",
		})
		return
	}

	// claims are the data that you want to store inside the jwt token
	// so whenever someone gives you a token you can decode it and get back this same claims
	claims := &models.Claims{
		UserId: user.ID,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	// generate jwt token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := token.SignedString([]byte(jwtSecret))

	c.JSON(200, gin.H{
		"message": "sign up successful",
		"token":   jwtTokenString,
		"data":    user,
	})
}
