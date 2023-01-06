package middleware

import (
	"net/http"

	"gateway/pkg/session"

	"github.com/julienschmidt/httprouter"
)

func Auth(next httprouter.Handle, sm session.SessionsManager) httprouter.Handle {
	return func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
		sess, err := sm.Check(r)
		if err != nil {
			http.Redirect(w, r, "/", http.StatusUnauthorized)
			return
		}
		ctx := session.ContextWithSession(r.Context(), sess)
		next(w, r.WithContext(ctx), ps)
	}
}
