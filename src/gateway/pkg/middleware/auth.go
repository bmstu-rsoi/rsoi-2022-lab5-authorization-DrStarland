package middleware

import (
	"net/http"

	"gateway/pkg/myjson"
	"gateway/pkg/session"

	"github.com/julienschmidt/httprouter"
	"go.uber.org/zap"
)

func Auth(next httprouter.Handle, sm session.SessionsManager) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		sess, err := sm.Check(r)
		if err != nil {
			if err == session.ErrNoAuth {
				myjson.JsonError(w, http.StatusUnauthorized, err.Error())
				return
			}
			myjson.JsonError(w, http.StatusUnauthorized, err.Error())
			return
		} else if sess == nil {
			myjson.JsonError(w, http.StatusUnauthorized, "")
			return
		}

		zapLogger, _ := zap.NewProduction()
		defer zapLogger.Sync() // flushes buffer, if any
		logger := zapLogger.Sugar()
		logger.Infoln("Token name: ", sess.Token.Subject)

		r.Header.Set("X-User-Name", sess.Token.Subject)
		ctx := session.ContextWithSession(r.Context(), sess)
		next(w, r.WithContext(ctx), ps)
	}
}
