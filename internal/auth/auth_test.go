package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		authHeader    string
		wantKey       string
		wantErr       bool
		expectedError error
	}{
		{
			name:       "Valid ApiKey header",
			authHeader: "ApiKey my-secret-key",
			wantKey:    "my-secret-key",
			wantErr:    false,
		},
		{
			name:          "No Authorization header",
			authHeader:    "",
			wantKey:       "",
			wantErr:       true,
			expectedError: ErrNoAuthHeaderIncluded,
		},
		{
			name:          "Malformed header - missing ApiKey prefix",
			authHeader:    "Bearer my-secret-key",
			wantKey:       "",
			wantErr:       true,
		},
		{
			name:          "Malformed header - only ApiKey",
			authHeader:    "ApiKey",
			wantKey:       "",
			wantErr:       true,
		},
		{
			name:          "Malformed header - missing key",
			authHeader:    "ApiKey ",
			wantKey:       "",
			wantErr:       false,
		},
		{
			name:          "Malformed header - extra spaces",
			authHeader:    "ApiKey    ",
			wantKey:       "",
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := http.Header{}
			if tt.authHeader != "" {
				headers.Set("Authorization", tt.authHeader)
			}
			gotKey, err := GetAPIKey(headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetAPIKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && tt.expectedError != nil && err != tt.expectedError {
				t.Errorf("GetAPIKey() error = %v, expectedError %v", err, tt.expectedError)
			}
			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() = %v, want %v", gotKey, tt.wantKey)
			}
		})
	}
}