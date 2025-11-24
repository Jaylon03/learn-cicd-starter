package auth

import (
	"errors"
	"net/http"
	"reflect"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		headers http.Header
		wantKey string
		wantErr error
	}{
		{
			name:    "No Authorization",
			headers: http.Header{},
			wantKey: "",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name: "Malformed Authorization header",
			headers: http.Header{
				"Authorization": []string{"Bearer abc123"},
			},
			wantKey: "",
			wantErr: errors.New("malformed authorization header"),
		},
		{
			name: "Correct ApiKey header",
			headers: http.Header{
				"Authorization": []string{"ApiKey mysecretkey"},
			},
			wantKey: "mysecretkey",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotErr := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() gotKey = %v; want %v", gotKey, tt.wantKey)
			}

			if !reflect.DeepEqual(gotErr, tt.wantErr) {
				t.Errorf("GetAPIKey() gotErr = %v; want %v", gotErr, tt.wantErr)
			}
		})
	}
}
