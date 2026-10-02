package api

import (
	"errors"
	"net/http"

	"github.com/veylvpn/backend/internal/config"
	"github.com/veylvpn/backend/internal/ovpn"
	"github.com/veylvpn/backend/internal/pki"
	"github.com/veylvpn/backend/internal/store"
)

const (
	CodeInvalidCredentials = "INVALID_CREDENTIALS"
	CodeInvalidToken       = "INVALID_ACCESS_TOKEN"
	CodeMaxDevices         = "MAX_DEVICES_REACHED"
	CodeDeviceNotFound     = "DEVICE_NOT_FOUND"
	CodeExpired            = "ACCOUNT_EXPIRED"
	CodeDisabled           = "ACCOUNT_DISABLED"
	CodeTooMany            = "TOO_MANY_REQUESTS"
	CodeInvalidInvite      = "INVALID_INVITE"
	CodeRegClosed          = "REGISTRATION_CLOSED"
	CodeInviteRequired     = "INVITE_REQUIRED"
	CodeBadRequest         = "BAD_REQUEST"
	CodeTooLarge           = "PAYLOAD_TOO_LARGE"
	CodeMediaType          = "UNSUPPORTED_MEDIA_TYPE"
	CodeClaimed            = "ACCOUNT_ALREADY_CLAIMED"
	CodeWeakPassword       = "WEAK_PASSWORD"
	CodeDeviceName         = "INVALID_DEVICE_NAME"
	CodeCSR                = "INVALID_CSR"
	CodeDNSCategory        = "INVALID_DNS_CATEGORY"
	CodeNotConfigured      = "NOT_CONFIGURED"
	CodeNotFound           = "NOT_FOUND"
	CodeMethod             = "METHOD_NOT_ALLOWED"
	CodeInternal           = "INTERNAL_ERROR"
)

var errNotConfigured = errors.New("server is not configured yet")

type apiError struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeErr(w http.ResponseWriter, status int, msg, code string) {
	writeJSON(w, status, apiError{Error: msg, Code: code})
}

func classify(err error) (int, string, string) {
	switch {
	case errors.Is(err, store.ErrBadCredentials), errors.Is(err, store.ErrNoAccount), errors.Is(err, store.ErrBadNumber):
		return http.StatusUnauthorized, "invalid credentials", CodeInvalidCredentials
	case errors.Is(err, store.ErrLocked):
		return http.StatusTooManyRequests, "too many attempts", CodeTooMany
	case errors.Is(err, store.ErrClaimed):
		return http.StatusConflict, "account already claimed", CodeClaimed
	case errors.Is(err, store.ErrDeviceLimit):
		return http.StatusConflict, "device limit reached", CodeMaxDevices
	case errors.Is(err, store.ErrNoDevice):
		return http.StatusNotFound, "unknown device", CodeDeviceNotFound
	case errors.Is(err, store.ErrWeakPassword):
		return http.StatusBadRequest, "password must be at least 10 characters", CodeWeakPassword
	case errors.Is(err, store.ErrBadName):
		return http.StatusBadRequest, "invalid device name", CodeDeviceName
	case errors.Is(err, pki.ErrBadCSR):
		return http.StatusBadRequest, "invalid csr", CodeCSR
	case errors.Is(err, store.ErrDisabled):
		return http.StatusForbidden, "account disabled", CodeDisabled
	case errors.Is(err, store.ErrExpired):
		return http.StatusForbidden, "account expired", CodeExpired
	case errors.Is(err, store.ErrBadInvite):
		return http.StatusForbidden, "invalid invite", CodeInvalidInvite
	case errors.Is(err, config.ErrCategory):
		return http.StatusBadRequest, "unknown dns blocking category", CodeDNSCategory
	case errors.Is(err, errNotConfigured), errors.Is(err, ovpn.ErrProfile):
		return http.StatusServiceUnavailable, "server is not configured yet", CodeNotConfigured
	default:
		return http.StatusInternalServerError, "server error", CodeInternal
	}
}

func fail(w http.ResponseWriter, err error) {
	status, msg, code := classify(err)
	if status == http.StatusTooManyRequests {
		w.Header().Set("Retry-After", "60")
	}
	writeErr(w, status, msg, code)
}
