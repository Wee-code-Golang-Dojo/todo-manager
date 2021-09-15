package jawt

import (
	"time"

	"github.com/Wee-code-Golang-Dojo/todo-manager/models"
	"github.com/dgrijalva/jwt-go"
)

const (
	jwtSecret = "secretname"
)

func ValidateToken(jwtToken string) (*models.Claims, error) {
	claims := &models.Claims{}

	keyFunc := func(token *jwt.Token) (i interface{}, e error) {
		return []byte(jwtSecret), nil
	}

	//  this function helps us validate the token
	// and if valid would store the claims inside the empty claims object we supplied to it (we supply a pointer)
	token, err := jwt.ParseWithClaims(jwtToken, claims, keyFunc)

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, err
	}

	return claims, nil
}

func CreateToken(userId string) (string, error) {
	// create and return a jwt token
	// claims are the data that you want to store inside the jwt token
	// so whenever someone gives you a token you can decode it and get back this same claims
	claims := &models.Claims{
		UserId: userId,
		StandardClaims: jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * 1).Unix(),
		},
	}

	// generate jwt token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtTokenString, err := token.SignedString([]byte(jwtSecret))
	if err != nil {
		return "", err
	}

	return jwtTokenString, nil
}
