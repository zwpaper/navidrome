package nativeapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/navidrome/navidrome/log"
	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
)

const endlessPlaybackPreferenceKey = "ui.endlessPlayback"

type userPreferencesResponse struct {
	// A null value means this preference has not been saved on the server yet.
	EndlessPlayback *bool `json:"endlessPlayback"`
}

type updateUserPreferencesPayload struct {
	EndlessPlayback *bool `json:"endlessPlayback"`
}

func (api *Router) addUserPreferencesRoute(r chi.Router) {
	r.Route("/user/preferences", func(r chi.Router) {
		r.Get("/", getUserPreferences(api.ds))
		r.Put("/", updateUserPreferences(api.ds))
	})
}

func authenticatedUser(w http.ResponseWriter, r *http.Request) (model.User, bool) {
	user, ok := request.UserFrom(r.Context())
	if !ok {
		http.Error(w, "authentication required", http.StatusUnauthorized)
	}
	return user, ok
}

func getUserPreferences(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedUser(w, r)
		if !ok {
			return
		}

		value, err := ds.UserProps(r.Context()).Get(user.ID, endlessPlaybackPreferenceKey)
		var endlessPlayback *bool
		switch {
		case errors.Is(err, model.ErrNotFound):
			// Keep this nil so the UI can migrate its existing local preference.
		case err != nil:
			log.Error(r.Context(), "Error reading user preferences", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		default:
			parsed, err := strconv.ParseBool(value)
			if err != nil {
				log.Error(r.Context(), "Invalid endless playback preference", "value", value, err)
				http.Error(w, "invalid stored preference", http.StatusInternalServerError)
				return
			}
			endlessPlayback = &parsed
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(userPreferencesResponse{
			EndlessPlayback: endlessPlayback,
		}); err != nil {
			log.Error(r.Context(), "Error encoding user preferences", err)
		}
	}
}

func updateUserPreferences(ds model.DataStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := authenticatedUser(w, r)
		if !ok {
			return
		}

		var payload updateUserPreferencesPayload
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&payload); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if payload.EndlessPlayback == nil {
			http.Error(w, "endlessPlayback is required", http.StatusBadRequest)
			return
		}

		value := strconv.FormatBool(*payload.EndlessPlayback)
		if err := ds.UserProps(r.Context()).Put(user.ID, endlessPlaybackPreferenceKey, value); err != nil {
			log.Error(r.Context(), "Error updating user preferences", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
