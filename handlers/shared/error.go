package shared

import (
	"net/http"
	"net/url"
)

// RestartLogin bounces the user back to the start of the sign-in flow when the
// login challenge is missing or expired. The original authorize parameters
// (client_id, redirect_uri, PKCE, …) live only inside the now-gone challenge, so
// the exact request can't be rebuilt — instead we redirect to the configured
// login URL, which re-initiates OAuth from scratch. Falls back to a plain
// message only when no login URL is configured.
func RestartLogin(w http.ResponseWriter, r *http.Request, loginURL string) {
	if loginURL == "" {
		http.Error(w, "Your sign-in session expired. Please start again.", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, loginURL, http.StatusFound)
}

func RedirectError(w http.ResponseWriter, r *http.Request, redirectURI, state, code, description string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	q := u.Query()
	q.Set("error", code)
	if state != "" {
		q.Set("state", state)
	}
	if description != "" {
		q.Set("error_description", description)
	}
	u.RawQuery = q.Encode()

	http.Redirect(w, r, u.String(), http.StatusFound)
}
