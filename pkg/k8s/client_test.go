// Copyright 2022 Tetrate
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package k8s

import (
	"errors"
	"testing"

	corev1 "k8s.io/api/core/v1"
)

func TestCheckJWTPolicy(t *testing.T) {
	testCases := []struct {
		name          string
		configFile    corev1.ConfigMap
		expectedError error
	}{
		{
			name:       "more secure jwt policy configured as third-party-jwt",
			configFile: corev1.ConfigMap{Data: map[string]string{"values": `{"global": {"jwtPolicy": "third-party-jwt"}}`}},
		},
		{
			name:          "less secure jwt policy configured",
			configFile:    corev1.ConfigMap{Data: map[string]string{"values": `{"global": {"jwtPolicy": "something-default"}}`}},
			expectedError: errors.New(JWTPolicyConfigError),
		},
		{
			name:          "jwt policy not configured",
			configFile:    corev1.ConfigMap{Data: map[string]string{}},
			expectedError: errors.New(JWTPolicyUnknownError),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actualError := checkUses3rdPartyJWT(&tc.configFile)
			validator(actualError, tc.expectedError, t)
		})
	}
}

func validator(actualError, expectedError error, t *testing.T) {
	if actualError != nil && expectedError != nil {
		if actualError.Error() != expectedError.Error() {
			t.Fatalf("expected %v but got %v", expectedError, actualError)
		}
	}
}
