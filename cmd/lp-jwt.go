/*
 * Minio Cloud Storage, (C) 2016, 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package cmd

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	jwtreq "github.com/dgrijalva/jwt-go/request"
)

const (
	jwtAlgorithm_lp = "Bearer"

	// Default JWT token for web handlers is one day.
	defaultJWTExpiry_lp = 24 * time.Hour

	// Inter-node JWT token expiry is 100 years approx.
	defaultInterNodeJWTExpiry_lp = 100 * 365 * 24 * time.Hour
)

var (
	errInvalidAccessKeyID_lp   = errors.New("The access key ID you provided does not exist in our records")
	errChangeCredNotAllowed_lp = errors.New("Changing access key and secret key not allowed")
	errAuthentication_lp       = errors.New("Authentication failed, check your access credentials")
	errNoAuthToken_lp          = errors.New("JWT token missing")
)

func authenticateJWT_lp(accessKey, secretKey string, expiry time.Duration) (string, error) {
	passedCredential, err := createCredential(accessKey, secretKey)
	if err != nil {
		return "", err
	}

	serverCred := serverConfig.GetCredential()

	if serverCred.AccessKey != passedCredential.AccessKey {
		// 调用 GetCredential_lp 获取指定租户的凭证
		serverCred = GetCredential_lp(passedCredential.AccessKey)
		// return "", errInvalidAccessKeyID_lp
	}

	if !serverCred.Equal(passedCredential) {
		return "", errAuthentication_lp
	}

	utcNow := UTCNow()
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.MapClaims{
		"exp": utcNow.Add(expiry).Unix(),
		"iat": utcNow.Unix(),
		"sub": accessKey,
	})

	return token.SignedString([]byte(serverCred.SecretKey))
}

func authenticateNode_lp(accessKey, secretKey string) (string, error) {
	return authenticateJWT_lp(accessKey, secretKey, defaultInterNodeJWTExpiry_lp)
}

func authenticateWeb_lp(accessKey, secretKey string) (string, error) {
	return authenticateJWT_lp(accessKey, secretKey, defaultJWTExpiry_lp)
}

func keyFuncCallback_lp(jwtToken *jwtgo.Token) (interface{}, error) {
	if _, ok := jwtToken.Method.(*jwtgo.SigningMethodHMAC); !ok {
		return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
	}

	return []byte(serverConfig.GetCredential().SecretKey), nil
}

func isAuthTokenValid_lp(tokenString string) bool {
	jwtToken, err := jwtgo.Parse(tokenString, keyFuncCallback)
	if err != nil {
		errorIf(err, "Unable to parse JWT token string")
		return false
	}

	return jwtToken.Valid
}

func isHTTPRequestValid_lp(req *http.Request) bool {
	return webRequestAuthenticate_lp(req) == nil
}

// Check if the request is authenticated.
// Returns nil if the request is authenticated. errNoAuthToken if token missing.
// Returns errAuthentication for all other errors.
func webRequestAuthenticate_lp(req *http.Request) error {
	jwtToken, err := jwtreq.ParseFromRequest(req, jwtreq.AuthorizationHeaderExtractor, keyFuncCallback)
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return errNoAuthToken_lp
		}
		return errAuthentication_lp
	}

	if !jwtToken.Valid {
		return errAuthentication_lp
	}
	return nil
}
