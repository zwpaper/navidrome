package nativeapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"

	"github.com/navidrome/navidrome/model"
	"github.com/navidrome/navidrome/model/request"
	"github.com/navidrome/navidrome/tests"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("User Preferences Endpoints", func() {
	var (
		ds       *tests.MockDataStore
		repo     *tests.MockedUserPropsRepo
		user     model.User
		withUser = func(req *http.Request) *http.Request {
			return req.WithContext(request.WithUser(req.Context(), user))
		}
	)

	BeforeEach(func() {
		repo = &tests.MockedUserPropsRepo{}
		ds = &tests.MockDataStore{MockedUserProps: repo}
		user = model.User{ID: "user-1", UserName: "user"}
	})

	Describe("GET /user/preferences", func() {
		It("returns null when the preference has not been saved", func() {
			req := withUser(httptest.NewRequest(http.MethodGet, "/user/preferences", nil))
			w := httptest.NewRecorder()

			getUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response userPreferencesResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.EndlessPlayback).To(BeNil())
		})

		It("returns the saved preference", func() {
			Expect(repo.Put(user.ID, endlessPlaybackPreferenceKey, "true")).To(Succeed())
			req := withUser(httptest.NewRequest(http.MethodGet, "/user/preferences", nil))
			w := httptest.NewRecorder()

			getUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusOK))
			var response userPreferencesResponse
			Expect(json.Unmarshal(w.Body.Bytes(), &response)).To(Succeed())
			Expect(response.EndlessPlayback).ToNot(BeNil())
			Expect(*response.EndlessPlayback).To(BeTrue())
		})

		It("requires an authenticated user", func() {
			req := httptest.NewRequest(http.MethodGet, "/user/preferences", nil)
			w := httptest.NewRecorder()

			getUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusUnauthorized))
		})

		It("returns an error when the stored value is invalid", func() {
			Expect(repo.Put(user.ID, endlessPlaybackPreferenceKey, "invalid")).To(Succeed())
			req := withUser(httptest.NewRequest(http.MethodGet, "/user/preferences", nil))
			w := httptest.NewRecorder()

			getUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusInternalServerError))
		})
	})

	Describe("PUT /user/preferences", func() {
		It("saves the preference for the authenticated user", func() {
			body := bytes.NewBufferString(`{"endlessPlayback":true}`)
			req := withUser(httptest.NewRequest(http.MethodPut, "/user/preferences", body))
			w := httptest.NewRecorder()

			updateUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusNoContent))
			value, err := repo.Get(user.ID, endlessPlaybackPreferenceKey)
			Expect(err).ToNot(HaveOccurred())
			Expect(value).To(Equal("true"))
		})

		It("rejects a missing preference", func() {
			req := withUser(httptest.NewRequest(
				http.MethodPut,
				"/user/preferences",
				bytes.NewBufferString(`{}`),
			))
			w := httptest.NewRecorder()

			updateUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusBadRequest))
		})

		It("returns an error when persistence fails", func() {
			repo.Error = errors.New("database unavailable")
			body := bytes.NewBufferString(`{"endlessPlayback":false}`)
			req := withUser(httptest.NewRequest(http.MethodPut, "/user/preferences", body))
			w := httptest.NewRecorder()

			updateUserPreferences(ds)(w, req)

			Expect(w.Code).To(Equal(http.StatusInternalServerError))
		})
	})
})
