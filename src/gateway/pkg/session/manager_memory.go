package session

import (
	"fmt"
	"gateway/pkg/models/user"
	"net/http"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

type MemorySessionsManager struct {
	data map[string]*Session
	mu   *sync.RWMutex
}

func NewSessionsManager() *MemorySessionsManager {
	return &MemorySessionsManager{
		data: make(map[string]*Session, 10),
		mu:   &sync.RWMutex{},
	}
}

func (sm *MemorySessionsManager) Check(r *http.Request) (*Session, error) {
	IncomingToken := r.Header.Get("authorization")
	// удаляем надпись в начале токена, поскольку она всегда одинакова -- можно "захардкодить"
	// Bearer_tokentokentokentoken
	IncomingToken = IncomingToken[7:]

	sm.mu.RLock()
	sess, ok := sm.data[IncomingToken]
	sm.mu.RUnlock()

	if !ok {
		return nil, ErrNoAuth
	}

	inToken := IncomingToken

	hashSecretGetter := func(token *jwt.Token) (interface{}, error) {
		method, ok := token.Method.(*jwt.SigningMethodHMAC)
		if !ok || method.Alg() != "HS256" {
			return nil, fmt.Errorf("bad sign method")
		}
		return ExampleTokenSecret, nil
	}
	token, err := jwt.Parse(inToken, hashSecretGetter)
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("bad token")
	}

	_, ok = token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("empty")
	}

	return sess, nil
}

func (sm *MemorySessionsManager) Create(w http.ResponseWriter, user user.User) (*Session, error) {
	sess := NewSession(user)

	sm.mu.Lock()
	sm.data[sess.Token] = sess
	sm.mu.Unlock()
	return sess, nil
}

func (sm *MemorySessionsManager) DestroyCurrent(w http.ResponseWriter, r *http.Request) error {
	sess, err := SessionFromContext(r.Context())
	if err != nil {
		return err
	}

	sm.mu.Lock()
	delete(sm.data, sess.Token)
	sm.mu.Unlock()

	return nil
}
