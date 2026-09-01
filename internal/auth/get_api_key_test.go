package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		hasHeader  bool
		wantKey    string
		wantErr    error
	}{
		{
			name:      "returns error when authorization header is missing",
			hasHeader: false,
			wantErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:       "returns error when header has no space-separated scheme",
			authHeader: "abc123",
			hasHeader:  true,
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "returns error when scheme is not ApiKey",
			authHeader: "Bearer abc123",
			hasHeader:  true,
			wantErr:    errors.New("malformed authorization header"),
		},
		{
			name:       "returns the key for a well formed ApiKey header",
			authHeader: "ApiKey abc123",
			hasHeader:  true,
			wantKey:    "abc123",
		},
		{
			name:       "returns only the second field when header has extra parts",
			authHeader: "ApiKey abc123 extra",
			hasHeader:  true,
			wantKey:    "abc123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Arrange
			headers := http.Header{}
			if tt.hasHeader {
				headers.Set("Authorization", tt.authHeader)
			}

			// Act
			gotKey, gotErr := GetAPIKey(headers)

			// Assert
			if tt.wantErr != nil {
				if gotErr == nil || gotErr.Error() != tt.wantErr.Error() {
					t.Fatalf("expected error %q, got %v", tt.wantErr, gotErr)
				}
				return
			}
			if gotErr != nil {
				t.Fatalf("expected no error, got %v", gotErr)
			}
			if gotKey != tt.wantKey {
				t.Fatalf("expected key %q, got %q", tt.wantKey, gotKey)
			}
		})
	}
}
