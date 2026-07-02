package shared

import (
	"net/http"
	"time"

	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/utils"
)

const (
	ssoSessionCookie = "sso_session"
	ssoSessionTTL    = 30 * 24 * time.Hour
)

// EstablishSSOSession signs userID into this device's SSO session. When a valid
// sso_session cookie is already present, the account is added to that session so
// one device can hold several accounts. Otherwise a new session is minted. The
// sso_session cookie is (re)written either way.
func EstablishSSOSession(redis *cache.RedisStore, w http.ResponseWriter, r *http.Request, userID string) error {
	token, err := existingSSOToken(redis, r)
	if err != nil {
		token = utils.GenerateRandomString(32)
		if err := redis.SaveSSOSession(r.Context(), token, userID, ssoSessionTTL); err != nil {
			return err
		}
		setSSOCookie(w, token)
		return nil
	}

	if err := redis.AddSSOAccount(r.Context(), token, userID, ssoSessionTTL); err != nil {
		return err
	}
	setSSOCookie(w, token)
	return nil
}

// existingSSOToken returns the session token from the request when it points to
// a live session, so a second sign-in extends it rather than replacing it.
func existingSSOToken(redis *cache.RedisStore, r *http.Request) (string, error) {
	cookie, err := r.Cookie(ssoSessionCookie)
	if err != nil {
		return "", err
	}
	if _, err := redis.GetSSOAccounts(r.Context(), cookie.Value); err != nil {
		return "", err
	}
	return cookie.Value, nil
}

func setSSOCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     ssoSessionCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(ssoSessionTTL.Seconds()),
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	})
}
