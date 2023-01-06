package session

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/MicahParks/keyfunc"
	jwt "github.com/golang-jwt/jwt/v4"
	"go.uber.org/zap"
)

const RawJWKS = `{"keys":[{"kty":"RSA","alg":"RS256","kid":"owcDPUuU5QB8_ojBnoIVl9pbb3iPsSc15cenVbavZQo","use":"sig","e":"AQAB","n":"quqU1buEQMDreTIXabUD491R05xrBpTkn5mf9JUtRWjtFp1qj5mQ7fpagYrs0nxbnJtHESbdTnoF1bsUT4qmXnldOC7VrZZr4mW3fhlNjF176yF4mFSjqCcRaj3uELBc2vbpEn-xasS0oyjr-pQ9n5MGQWkHCUzDm1yigunTYqIALnRFLBLTesXWzKyFHggvTeIjgVt-kPDPjn8bzwQrZC4MC0s-gmgHXZnY7wQMCJ33satSzrbe_XikoJsyKEUfeU3SKjd_MVhuvvvWSv9BUJWsgUzxySnBSGxIlydYPqVdLB6YN4sEItRBbLC0_0m3uYyAQpew7IaHda7yQoIW9Q"}]}`

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

func newJWKs(rawJWKS string) *keyfunc.JWKS {
	jwksJSON := json.RawMessage(rawJWKS)
	jwks, err := keyfunc.NewJSON(jwksJSON)
	if err != nil {
		panic(err)
	}
	return jwks
}

func (sm *MemorySessionsManager) Check(r *http.Request) (*Session, error) {
	IncomingToken := r.Header.Get("Authorization")
	if len(IncomingToken) == 0 {
		return nil, fmt.Errorf("no Authorization header") // token is missing
	}

	zapLogger, _ := zap.NewProduction()
	defer zapLogger.Sync() // flushes buffer, if any
	logger := zapLogger.Sugar()
	logger.Infoln("Token: ", IncomingToken)

	// удаляем надпись в начале токена, поскольку она всегда одинакова -- можно "захардкодить"
	// Bearer_tokentokentokentoken
	IncomingToken = IncomingToken[7:]

	sess := &Session{}
	jwks := newJWKs(RawJWKS)
	token, err := jwt.ParseWithClaims(IncomingToken, sess.Token, jwks.Keyfunc)

	logger.Infoln(": ", jwks, token)

	if err != nil || !token.Valid {
		return nil, ErrNoAuth // Access Denied
	}

	if time.Now().Unix()-sess.Token.ExpiresAt > 0 {
		return nil, fmt.Errorf("jwt-token expire") // TokenExpired
	}

	return sess, nil

	// sm.mu.RLock()
	// sess, ok := sm.data[IncomingToken]
	// sm.mu.RUnlock()

	// if !ok {
	// 	return nil, ErrNoAuth
	// }

	// // inToken := IncomingToken

	// // hashSecretGetter := func(token *jwt.Token) (interface{}, error) {
	// // 	method, ok := token.Method.(*jwt.SigningMethodHMAC)
	// // 	if !ok || method.Alg() != "HS256" {
	// // 		return nil, fmt.Errorf("bad sign method")
	// // 	}
	// // 	return ExampleTokenSecret, nil
	// // }
	// // token, err := jwt.Parse(inToken, hashSecretGetter)
	// // if err != nil || !token.Valid {
	// // 	return nil, fmt.Errorf("bad token")
	// // }

	// // _, ok = token.Claims.(jwt.MapClaims)
	// // if !ok {
	// // 	return nil, fmt.Errorf("empty")
	// // }

	// return sess, nil
}

// func (sm *MemorySessionsManager) Create(w http.ResponseWriter, user user.User) (*Session, error) {
// 	// sess := NewSession(user)

// 	// sm.mu.Lock()
// 	// sm.data[sess.Token] = sess
// 	// sm.mu.Unlock()
// 	return sess, nil
// }

// func (sm *MemorySessionsManager) DestroyCurrent(w http.ResponseWriter, r *http.Request) error {
// 	sess, err := SessionFromContext(r.Context())
// 	if err != nil {
// 		return err
// 	}

// 	sm.mu.Lock()
// 	delete(sm.data, sess.Token)
// 	sm.mu.Unlock()

// 	return nil
// }
