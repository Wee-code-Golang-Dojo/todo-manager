package models

import (
	"time"

	"github.com/dgrijalva/jwt-go"
)

type User struct {
	ID       string    `json:"id" bson:"id"`
	Name     string    `json:"name" bson:"name"`
	Email    string    `json:"email" bson:"email"`
	Password string    `json:"-,omitempty" bson:"password"`
	Ts       time.Time `json:"timestamp" bson:"timestamp"`
}

type Task struct {
	ID          string    `json:"id"`
	Owner       string    `json:"owner"`
	Name        string    `json:"name"`
	Description string    `json:"description`
	Ts          time.Time `json:"timestamp"`
}

type Claims struct {
	UserId string `json:"user_id"`
	jwt.StandardClaims
}
