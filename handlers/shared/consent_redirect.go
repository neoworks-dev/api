package shared

import (
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/neoworks/auth/oauth"
	"github.com/neoworks/auth/storage/cache"
	"github.com/neoworks/auth/storage/database"
	"github.com/neoworks/auth/utils"
)

func HandleConsentRedirect(
	redis *cache.RedisStore,
	store *database.SurrealStore,
	issuer *oauth.TokenIssuer,
	user *oauth.User,
	loginChallenge *oauth.LoginChallenge,
	response http.ResponseWriter,
	request *http.Request,
) {
	ctx := request.Context()

	// Pin the resolved account to the consent step. The consent page reads this
	// short-lived login_session (not the multi-account sso_session) so it always
	// authorizes the exact account the user picked.
	if userID, ok := user.ID.ID.(string); ok {
		if sessionToken, err := issuer.IssueSessionToken(userID); err == nil {
			http.SetCookie(response, &http.Cookie{
				Name:     "login_session",
				Value:    sessionToken,
				Path:     "/oauth",
				MaxAge:   10 * 60,
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteLaxMode,
			})
		}
	}

	client, err := store.GetClient(ctx, loginChallenge.ClientID)
	if err != nil {
		slog.WarnContext(
			ctx, "failed to fetch client",
			"client_id", loginChallenge.ClientID,
			"error", err,
		)

		http.Error(response, "Invalid client", http.StatusUnauthorized)
		return
	}

	if client.AutoGrantScopes {

		err := redis.DeleteLoginChallenge(ctx, loginChallenge.ID)
		if err != nil {
			slog.WarnContext(
				ctx, "failed to delete login challenge",
				"login_challenge_id", loginChallenge.ID,
				"error", err,
			)

			http.Error(response, "Invalid login challenge", http.StatusBadRequest)
			return
		}

		authCode := utils.GenerateRandomString(32)
		authCodeExpiresAt := time.Now().Add(10 * time.Minute)

		authCodePayload := oauth.AuthCode{
			Code:                authCode,
			UserID:              user.ID,
			ClientID:            client.ID,
			Scopes:              loginChallenge.Scopes,
			RedirectURI:         loginChallenge.RedirectURI,
			CodeChallenge:       loginChallenge.CodeChallenge,
			CodeChallengeMethod: loginChallenge.CodeChallengeMethod,
			ExpiresAt:           authCodeExpiresAt,
		}

		err = redis.SaveAuthCode(ctx, authCodePayload)
		if err != nil {
			slog.ErrorContext(
				ctx, "failed to save auth code",
				"user_id", user.ID,
				"client_id", client.ID,
				"error", err,
			)

			http.Error(response, "Failed to save auth code", http.StatusInternalServerError)
			return
		}

		grant := &oauth.Grant{
			User:    user.ID,
			Client:  client.ID,
			Scopes:  loginChallenge.Scopes,
			Enabled: true,
		}

		if err := store.UpsertGrant(ctx, grant); err != nil {
			slog.ErrorContext(
				ctx, "failed to upsert grant",
				"user_id", grant.User,
				"client_id", grant.Client,
				"scopes", grant.Scopes,
				"enabled", grant.Enabled,
				"error", err,
			)

			http.Error(response, "Failed to save grant", http.StatusInternalServerError)
			return
		}

		// Redirect back to the client with the authorization code and state

		redirectURL, err := url.Parse(loginChallenge.RedirectURI)
		if err != nil {
			slog.ErrorContext(
				ctx, "invalid redirect URI",
				"redirect_uri", loginChallenge.RedirectURI,
				"error", err,
			)

			http.Error(response, "Invalid redirect URI", http.StatusBadRequest)
		}

		q := redirectURL.Query()
		q.Set("code", authCode)
		q.Set("state", loginChallenge.State)
		redirectURL.RawQuery = q.Encode()

		http.Redirect(response, request, redirectURL.String(), http.StatusFound)
	} else {
		redirectURL := &url.URL{
			Scheme: "http",
			Host:   request.Host,
			Path:   "/oauth/consent",
		}

		q := redirectURL.Query()
		q.Set("login_challenge", loginChallenge.ID)
		redirectURL.RawQuery = q.Encode()

		http.Redirect(response, request, redirectURL.String(), http.StatusFound)
	}
}
