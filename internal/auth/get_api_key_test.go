package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := map[string]struct {
		header      string
		setHeader   bool
		wantKey     string
		wantErr     bool
		wantErrType error
	}{
		"valid api key": {
			header:    "ApiKey abc123",
			setHeader: true,
			wantKey:   "abc123",
		},
		"no authorization header": {
			setHeader:   false,
			wantErr:     true,
			wantErrType: ErrNoAuthHeaderIncluded,
		},
		"empty authorization header": {
			header:      "",
			setHeader:   true,
			wantErr:     true,
			wantErrType: ErrNoAuthHeaderIncluded,
		},
		"wrong scheme": {
			header:    "Bearer abc123",
			setHeader: true,
			wantErr:   true,
		},
		"missing key": {
			header:    "ApiKey",
			setHeader: true,
			wantErr:   true,
		},
		"lowercase scheme": {
			header:    "apikey abc123",
			setHeader: true,
			wantErr:   true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			headers := http.Header{}
			if tc.setHeader {
				headers.Set("Authorization", tc.header)
			}

			got, err := GetAPIKey(headers)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (key %q)", got)
				}
				if tc.wantErrType != nil && !errors.Is(err, tc.wantErrType) {
					t.Fatalf("expected error %v, got %v", tc.wantErrType, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantKey {
				t.Fatalf("expected key %q, got %q", tc.wantKey, got)
			}
		})
	}
}
