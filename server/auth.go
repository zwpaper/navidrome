package server

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/deluan/rest"
	"github.com/go-chi/jwtauth/v5"
	"github.com/navidrome/navidrome/conf"
	"github.com/navidrome/navidrome/consts"
	"github.com/navidrome/navidrome/core/auth"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/id"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/utils/gravatar"
	"golang.org/x/oauth2"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

var (
	ErrNoUsers         = errors.New("no users created")
	ErrUnauthenticated = errors.New("request not authenticated")
)

func login(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := getCredentialsFromBody(r)
		if err != nil {
			log.Error(r, "Parsing request body", err)
			_ = rest.RespondWithError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}

		doLogin(ds, username, password, w, r)
	}
}

// buildAuthPayloadWithToken builds auth payload including JWT token
func buildAuthPayloadWithToken(user *model.User) (map[string]interface{}, error) {
	tokenString, err := auth.CreateToken(user)
	if err != nil {
		return nil, err
	}

	payload := buildAuthPayload(user)
	payload["token"] = tokenString

	return payload, nil
}

func doLogin(ds model.DataStore, username string, password string, w http.ResponseWriter, r *http.Request) {
	user, err := validateLogin(ds.User(r.Context()), username, password)
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authentication user. Please try again")
		return
	}
	if user == nil {
		log.Warn(r, "Unsuccessful login", "username", username, "request", r.Header)
		_ = rest.RespondWithError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	payload, err := buildAuthPayloadWithToken(user)
	if err != nil {
		_ = rest.RespondWithError(w, http.StatusInternalServerError, "Unknown error authenticating user. Please try again")
		return
	}
	_ = rest.RespondWithJSON(w, http.StatusOK, payload)
}

func buildAuthPayload(user *model.User) map[string]interface{} {
	payload := map[string]interface{}{
		"id":       user.ID,
		"name":     user.Name,
		"username": user.UserName,
		"isAdmin":  user.IsAdmin,
	}
	if conf.Server.EnableGravatar && user.Email != "" {
		payload["avatar"] = gravatar.Url(user.Email, 50)
	}

	bytes := make([]byte, 3)
	_, err := rand.Read(bytes)
	if err != nil {
		log.Error("Could not create subsonic salt", "user", user.UserName, err)
		return payload
	}
	subsonicSalt := hex.EncodeToString(bytes)
	payload["subsonicSalt"] = subsonicSalt

	subsonicToken := md5.Sum([]byte(user.Password + subsonicSalt))
	payload["subsonicToken"] = hex.EncodeToString(subsonicToken[:])

	return payload
}

func getCredentialsFromBody(r *http.Request) (username string, password string, err error) {
	data := make(map[string]string)
	decoder := json.NewDecoder(r.Body)
	if err = decoder.Decode(&data); err != nil {
		log.Error(r, "parsing request body", err)
		err = errors.New("invalid request payload")
		return
	}
	username = data["username"]
	password = data["password"]
	return username, password, nil
}

func createAdmin(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, err := getCredentialsFromBody(r)
		if err != nil {
			log.Error(r, "parsing request body", err)
			_ = rest.RespondWithError(w, http.StatusUnprocessableEntity, err.Error())
			return
		}
		c, err := ds.User(r.Context()).CountAll()
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if c > 0 {
			_ = rest.RespondWithError(w, http.StatusForbidden, "Cannot create another first admin")
			return
		}
		err = createAdminUser(r.Context(), ds, username, password)
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, err.Error())
			return
		}
		doLogin(ds, username, password, w, r)
	}
}

func createAdminUser(ctx context.Context, ds model.DataStore, username, password string) error {
	log.Warn(ctx, "Creating initial user", "user", username)
	now := time.Now()
	caser := cases.Title(language.Und)
	initialUser := model.User{
		ID:          id.NewRandom(),
		UserName:    username,
		Name:        caser.String(username),
		Email:       "",
		NewPassword: password,
		IsAdmin:     true,
		LastLoginAt: &now,
	}
	err := ds.User(ctx).Put(&initialUser)
	if err != nil {
		log.Error(ctx, "Could not create initial user", "user", initialUser, err)
	}
	return nil
}

func validateLogin(userRepo model.UserRepository, userName, password string) (*model.User, error) {
	u, err := userRepo.FindByUsernameWithPassword(userName)
	if errors.Is(err, model.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if u.Password != password {
		return nil, nil
	}
	err = userRepo.UpdateLastLoginAt(u.ID)
	if err != nil {
		log.Error("Could not update LastLoginAt", "user", userName)
	}
	return u, nil
}

func JWTVerifier(next http.Handler) http.Handler {
	return jwtauth.Verify(auth.TokenAuth, tokenFromHeader, tokenFromOIDCCookie, jwtauth.TokenFromCookie, jwtauth.TokenFromQuery)(next)
}

func tokenFromHeader(r *http.Request) string {
	// Get token from authorization header.
	bearer := r.Header.Get(consts.UIAuthorizationHeader)
	if len(bearer) > 7 && strings.ToUpper(bearer[0:6]) == "BEARER" {
		return bearer[7:]
	}
	return ""
}

// tokenFromOIDCCookie extracts JWT token from the OIDC auth cookie
func tokenFromOIDCCookie(r *http.Request) string {
	if !conf.Server.OIDC.Enabled {
		return ""
	}

	cookie, err := r.Cookie("oidc_auth_token")
	if err != nil {
		return ""
	}

	return cookie.Value
}

func UsernameFromToken(r *http.Request) string {
	token, claims, err := jwtauth.FromContext(r.Context())
	if err != nil || claims["sub"] == nil || token == nil {
		return ""
	}
	log.Trace(r, "Found username in JWT token", "username", token.Subject())
	return token.Subject()
}

// UsernameFromOIDCToken extracts username from OIDC JWT token
func UsernameFromOIDCToken(r *http.Request) string {
	if !conf.Server.OIDC.Enabled {
		return ""
	}

	// First check if we already have a token in context from JWTVerifier
	token, claims, err := jwtauth.FromContext(r.Context())
	if err == nil && claims["sub"] != nil && token != nil {
		log.Trace(r, "Found username in OIDC JWT token", "username", token.Subject())
		return token.Subject()
	}

	return ""
}

func UsernameFromReverseProxyHeader(r *http.Request) string {
	if conf.Server.ReverseProxyWhitelist == "" {
		return ""
	}
	reverseProxyIp, ok := request.ReverseProxyIpFrom(r.Context())
	if !ok {
		log.Error("ReverseProxyWhitelist enabled but no proxy IP found in request context. Please report this error.")
		return ""
	}
	if !validateIPAgainstList(reverseProxyIp, conf.Server.ReverseProxyWhitelist) {
		log.Warn(r.Context(), "IP is not whitelisted for reverse proxy login", "proxy-ip", reverseProxyIp, "client-ip", r.RemoteAddr)
		return ""
	}
	username := r.Header.Get(conf.Server.ReverseProxyUserHeader)
	if username == "" {
		return ""
	}
	log.Trace(r, "Found username in ReverseProxyUserHeader", "username", username)
	return username
}

func InternalAuth(r *http.Request) string {
	username, ok := request.InternalAuthFrom(r.Context())
	if !ok {
		return ""
	}
	log.Trace(r, "Found username in InternalAuth", "username", username)
	return username
}

func UsernameFromConfig(*http.Request) string {
	return conf.Server.DevAutoLoginUsername
}

func contextWithUser(ctx context.Context, ds model.DataStore, username string) (context.Context, error) {
	user, err := ds.User(ctx).FindByUsername(username)
	if err == nil {
		ctx = log.NewContext(ctx, "username", username)
		ctx = request.WithUsername(ctx, user.UserName)
		return request.WithUser(ctx, *user), nil
	}
	log.Error(ctx, "Authenticated username not found in DB", "username", username)
	return ctx, err
}

func authenticateRequest(ds model.DataStore, r *http.Request, findUsernameFns ...func(r *http.Request) string) (context.Context, error) {
	var username string
	for _, fn := range findUsernameFns {
		username = fn(r)
		if username != "" {
			break
		}
	}
	if username == "" {
		return nil, ErrUnauthenticated
	}

	return contextWithUser(r.Context(), ds, username)
}

func Authenticator(ds model.DataStore) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, err := authenticateRequest(ds, r, UsernameFromConfig, UsernameFromToken, UsernameFromOIDCToken, UsernameFromReverseProxyHeader)
			if err != nil {
				_ = rest.RespondWithError(w, http.StatusUnauthorized, "Not authenticated")
				return
			}

			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// JWTRefresher updates the expiry date of the received JWT token, and add the new one to the Authorization Header
func JWTRefresher(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		token, _, err := jwtauth.FromContext(ctx)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}
		newTokenString, err := auth.TouchToken(token)
		if err != nil {
			log.Error(r, "Could not sign new token", err)
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "Not authenticated")
			return
		}

		w.Header().Set(consts.UIAuthorizationHeader, newTokenString)
		next.ServeHTTP(w, r)
	})
}

func handleLoginFromHeaders(ds model.DataStore, r *http.Request) map[string]interface{} {
	username := UsernameFromConfig(r)
	if username == "" {
		username = UsernameFromReverseProxyHeader(r)
		if username == "" {
			return nil
		}
	}

	userRepo := ds.User(r.Context())
	user, err := userRepo.FindByUsernameWithPassword(username)
	if user == nil || err != nil {
		log.Info(r, "User passed in header not found", "user", username)
		// Check if this is the first user being created
		count, _ := userRepo.CountAll()
		isFirstUser := count == 0

		newUser := model.User{
			ID:          id.NewRandom(),
			UserName:    username,
			Name:        username,
			Email:       "",
			NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(),
			IsAdmin:     isFirstUser, // Make the first user an admin
		}
		err := userRepo.Put(&newUser)
		if err != nil {
			log.Error(r, "Could not create new user", "user", username, err)
			return nil
		}
		user, err = userRepo.FindByUsernameWithPassword(username)
		if user == nil || err != nil {
			log.Error(r, "Created user but failed to fetch it", "user", username)
			return nil
		}
	}

	err = userRepo.UpdateLastLoginAt(user.ID)
	if err != nil {
		log.Error(r, "Could not update LastLoginAt", "user", username, err)
		return nil
	}

	// Header authentication should not include JWT token
	return buildAuthPayload(user)
}

func validateIPAgainstList(ip string, comaSeparatedList string) bool {
	if comaSeparatedList == "" || ip == "" {
		return false
	}

	cidrs := strings.Split(comaSeparatedList, ",")

	// Per https://github.com/golang/go/issues/49825, the remote address
	// on a unix socket is '@'
	if ip == "@" && strings.HasPrefix(conf.Server.Address, "unix:") {
		return slices.Contains(cidrs, "@")
	}

	if net.ParseIP(ip) == nil {
		ip, _, _ = net.SplitHostPort(ip)
	}

	if ip == "" {
		return false
	}

	testedIP, _, err := net.ParseCIDR(fmt.Sprintf("%s/32", ip))
	if err != nil {
		return false
	}

	for _, cidr := range cidrs {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil && ipnet.Contains(testedIP) {
			return true
		}
	}

	return false
}

// OIDC Authentication handlers

func oidcLogin(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !conf.Server.OIDC.Enabled {
			_ = rest.RespondWithError(w, http.StatusNotFound, "OIDC not enabled")
			return
		}

		config, err := getOIDCConfig(r.Context())
		if err != nil {
			log.Error(r, "Failed to get OIDC configuration", err)
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "OIDC configuration error")
			return
		}

		state := generateStateToken()
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_state",
			Value:    state,
			Path:     "/",
			HttpOnly: true,
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600, // 10 minutes
		})

		authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)
		http.Redirect(w, r, authURL, http.StatusFound)
	}
}

func oidcCallback(ds model.DataStore) func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if !conf.Server.OIDC.Enabled {
			_ = rest.RespondWithError(w, http.StatusNotFound, "OIDC not enabled")
			return
		}

		fmt.Printf("Callback URL: %s\n", r.URL.String())
		fmt.Printf("Configured RedirectURI: %s\n", conf.Server.OIDC.RedirectURI)

		// Verify state token
		stateCookie, err := r.Cookie("oidc_state")
		if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
			log.Warn(r, "Invalid OIDC state token")
			_ = rest.RespondWithError(w, http.StatusBadRequest, "Invalid state token")
			return
		}

		// Clear state cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_state",
			Value:    "",
			Path:     "/",
			HttpOnly: true,
			MaxAge:   -1,
		})

		fmt.Println("OIDC Callback received")

		// Exchange code for token
		config, err := getOIDCConfig(r.Context())
		if err != nil {
			log.Error(r, "Failed to get OIDC configuration", err)
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "OIDC configuration error")
			return
		}

		token, err := config.Exchange(r.Context(), r.URL.Query().Get("code"))
		if err != nil {
			log.Error(r, "Failed to exchange OIDC code", err)
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "Failed to exchange authorization code")
			return
		}

		// Extract user info from ID token
		provider, err := oidc.NewProvider(r.Context(), conf.Server.OIDC.IssuerURL)
		if err != nil {
			log.Error(r, "Failed to create OIDC provider", err)
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "OIDC provider error")
			return
		}

		verifier := provider.Verifier(&oidc.Config{ClientID: conf.Server.OIDC.ClientID})
		rawIDToken, ok := token.Extra("id_token").(string)
		if !ok {
			log.Error(r, "No ID token in OIDC response")
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "No ID token received")
			return
		}

		idToken, err := verifier.Verify(r.Context(), rawIDToken)
		if err != nil {
			log.Error(r, "Failed to verify ID token", err)
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "Invalid ID token")
			return
		}

		var claims map[string]interface{}
		if err := idToken.Claims(&claims); err != nil {
			log.Error(r, "Failed to parse ID token claims", err)
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to parse user claims")
			return
		}

		// Extract user information
		email, _ := claims["email"].(string)
		name, _ := claims["name"].(string)
		username, _ := claims["preferred_username"].(string)

		// Check if user has admin privileges based on group claims
		isOIDCAdmin := checkOIDCAdminPrivileges(claims)

		// Fallback to email as username if preferred_username is not available
		if username == "" {
			username = email
		}

		if username == "" {
			log.Error(r, "No username found in OIDC claims", "claims", claims)
			_ = rest.RespondWithError(w, http.StatusUnauthorized, "No username found in OIDC claims")
			return
		}

		// Find or create user
		userRepo := ds.User(r.Context())
		user, err := userRepo.FindByUsername(username)
		if errors.Is(err, model.ErrNotFound) {
			// Check if this is the first user being created
			count, _ := userRepo.CountAll()
			isFirstUser := count == 0

			// User is admin if they're the first user OR they have the admin group in OIDC
			isAdmin := isFirstUser || isOIDCAdmin

			newUser := model.User{
				ID:          id.NewRandom(),
				UserName:    username,
				Name:        name,
				Email:       email,
				NewPassword: consts.PasswordAutogenPrefix + id.NewRandom(), // Auto-generated password
				IsAdmin:     isAdmin,
			}
			err := userRepo.Put(&newUser)
			if err != nil {
				log.Error(r, "Could not create new OIDC user", "user", username, err)
				_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to create user")
				return
			}
			user = &newUser

			if isOIDCAdmin && !isFirstUser {
				log.Info(r, "OIDC user created with admin privileges based on group membership", "user", username, "adminGroup", conf.Server.OIDC.AdminGroup)
			}
		} else if err != nil {
			log.Error(r, "Error finding OIDC user", "user", username, err)
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "User lookup error")
			return
		} else {
			// User exists - check if we need to update admin status based on group membership
			if isOIDCAdmin && !user.IsAdmin {
				user.IsAdmin = true
				err = userRepo.Put(user)
				if err != nil {
					log.Error(r, "Could not update OIDC user admin status", "user", username, err)
				} else {
					log.Info(r, "OIDC user promoted to admin based on group membership", "user", username, "adminGroup", conf.Server.OIDC.AdminGroup)
				}
			} else if !isOIDCAdmin && user.IsAdmin {
				// Optional: demote admin users who no longer have the admin group
				// Uncomment the following lines if you want to automatically demote users
				// user.IsAdmin = false
				// err = userRepo.Put(user)
				// if err != nil {
				//     log.Error(r, "Could not update OIDC user admin status", "user", username, err)
				// } else {
				//     log.Info(r, "OIDC user demoted from admin - no longer in admin group", "user", username, "adminGroup", conf.Server.OIDC.AdminGroup)
				// }
			}
		}

		// Update last login time
		err = userRepo.UpdateLastLoginAt(user.ID)
		if err != nil {
			log.Error(r, "Could not update LastLoginAt for OIDC user", "user", username, err)
		}

		// Reuse the login token logic
		payload, err := buildAuthPayloadWithToken(user)
		if err != nil {
			_ = rest.RespondWithError(w, http.StatusInternalServerError, "Failed to create authentication token")
			return
		}

		// Extract token for cookie
		tokenString := payload["token"].(string)

		// Set authentication cookie
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_auth_token",
			Value:    tokenString,
			Path:     "/",
			HttpOnly: false, // Allow JavaScript access for the auth provider
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   int(conf.Server.SessionTimeout.Seconds()),
		})

		payloadJson, err := json.Marshal(payload)
		if err != nil {
			log.Error(r, "Error converting auth payload to JSON", "payload", payload, err)
		}

		// Set payload cookie - encode to base64 to avoid invalid characters
		payloadEncoded := base64.StdEncoding.EncodeToString(payloadJson)
		http.SetCookie(w, &http.Cookie{
			Name:     "oidc_auth_payload",
			Value:    payloadEncoded,
			Path:     "/",
			HttpOnly: false, // Allow JavaScript access
			Secure:   r.TLS != nil,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   60, // Short-lived, just for the redirect
		})

		// Redirect to frontend
		http.Redirect(w, r, conf.Server.BasePath+consts.URLPathUI+"/?oidc_login=success", http.StatusFound)
	}
}

func getOIDCConfig(ctx context.Context) (*oauth2.Config, error) {
	provider, err := oidc.NewProvider(ctx, conf.Server.OIDC.IssuerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	return &oauth2.Config{
		ClientID:     conf.Server.OIDC.ClientID,
		ClientSecret: conf.Server.OIDC.ClientSecret,
		RedirectURL:  conf.Server.OIDC.RedirectURI,
		Endpoint:     provider.Endpoint(),
		Scopes:       conf.Server.OIDC.Scopes,
	}, nil
}

func generateStateToken() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// checkOIDCAdminPrivileges checks if the user has admin privileges based on group claims
func checkOIDCAdminPrivileges(claims map[string]interface{}) bool {
	// If no admin group is configured, don't grant admin privileges
	if conf.Server.OIDC.AdminGroup == "" {
		return false
	}

	// Check for groups claim in various possible formats
	groups := extractGroupsClaim(claims)

	// Check if the admin group is present in the user's groups
	for _, group := range groups {
		if group == conf.Server.OIDC.AdminGroup {
			return true
		}
	}

	return false
}

// extractGroupsClaim extracts groups from claims in various possible formats
func extractGroupsClaim(claims map[string]interface{}) []string {
	var groups []string

	// Try different possible claim names for groups
	groupClaimNames := []string{"groups", "group", "roles", "role"}

	for _, claimName := range groupClaimNames {
		if groupsInterface, exists := claims[claimName]; exists {
			switch groupsValue := groupsInterface.(type) {
			case []interface{}:
				// Groups as array of interfaces
				for _, group := range groupsValue {
					if groupStr, ok := group.(string); ok {
						groups = append(groups, groupStr)
					}
				}
			case []string:
				// Groups as array of strings
				groups = append(groups, groupsValue...)
			case string:
				// Single group as string
				groups = append(groups, groupsValue)
			}

			// If we found groups in this claim, use them
			if len(groups) > 0 {
				break
			}
		}
	}

	return groups
}
