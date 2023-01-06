package middleware

import (
	"net/http"

	"gateway/pkg/myjson"
	"gateway/pkg/session"

	"github.com/julienschmidt/httprouter"
)

func Auth(next httprouter.Handle, sm session.SessionsManager) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		sess, err := sm.Check(r)
		if err != nil {
			if err == session.ErrNoAuth {
				myjson.JsonError(w, http.StatusUnauthorized, err.Error())
			}
			myjson.JsonError(w, http.StatusUnauthorized, err.Error())
			return
		}

		r.Header.Set("X-User-Name", sess.Token.Subject)
		ctx := session.ContextWithSession(r.Context(), sess)
		next(w, r.WithContext(ctx), ps)
	}
}
