package session

import (
	"context"
	"errors"
	"gateway/pkg/models/user"
	"log"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
)

var (
	ErrNoAuth = errors.New("no session found")
)

type sessKey string

var SessionKey sessKey = "User_Token"

type Session struct {
	Token string    `json:"token"`
	User  user.User `json:"omit"`
}

type LoginForm struct {
	Login    string `json:"username"`
	Password string `json:"password"`
}

var (
	ExamplePassword    = "lovelove"
	ExampleTokenSecret = []byte("супер секретный ключ")
)

func NewSession(fd user.User) *Session {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user": jwt.MapClaims{
			"username": fd.Username,
			"id":       fd.ID,
		},
		"iat": time.Now().Unix(),
		"exp": time.Now().Unix() + int64(time.Hour*24*4),
	})
	tokenString, err := token.SignedString(ExampleTokenSecret)
	if err != nil {
		log.Println(err.Error())
	}

	return &Session{
		Token: tokenString,
		User:  fd,
	}
}

func SessionFromContext(ctx context.Context) (*Session, error) {
	sess, ok := ctx.Value(SessionKey).(*Session)
	if !ok || sess == nil {
		return nil, ErrNoAuth
	}
	return sess, nil
}

func ContextWithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, SessionKey, sess)
}
