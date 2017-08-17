/*
 * Minio Cloud Storage, (C) 2015, 2016 Minio, Inc.
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
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

// Verify if the request http Header "x-amz-content-sha256" == "UNSIGNED-PAYLOAD"
func isRequestUnsignedPayload_lp(r *http.Request) bool {
	return r.Header.Get("x-amz-content-sha256") == unsignedPayload
}

// Verify if request has JWT.
func isRequestJWT_lp(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), jwtAlgorithm)
}

// Verify if request has AWS Signature Version '4'.
func isRequestSignatureV4_lp(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm)
}

// Verify if request has AWS Signature Version '2'.
func isRequestSignatureV2_lp(r *http.Request) bool {
	return (!strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm) &&
		strings.HasPrefix(r.Header.Get("Authorization"), signV2Algorithm))
}

// Verify if request has AWS PreSign Version '4'.
func isRequestPresignedSignatureV4_lp(r *http.Request) bool {
	_, ok := r.URL.Query()["X-Amz-Credential"]
	return ok
}

// Verify request has AWS PreSign Version '2'.
func isRequestPresignedSignatureV2_lp(r *http.Request) bool {
	_, ok := r.URL.Query()["AWSAccessKeyId"]
	return ok
}

// Verify if request has AWS Post policy Signature Version '4'.
func isRequestPostPolicySignatureV4_lp(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") && r.Method == httpPOST
}

// Verify if the request has AWS Streaming Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestSignStreamingV4_lp(r *http.Request) bool {
	return r.Header.Get("x-amz-content-sha256") == streamingContentSHA256 &&
		r.Method == httpPUT
}

// Authorization type.
type authType_lp int

// List of all supported auth types.
const (
	authTypeUnknown_lp authType_lp = iota
	authTypeAnonymous_lp
	authTypePresigned_lp
	authTypePresignedV2_lp
	authTypePostPolicy_lp
	authTypeStreamingSigned_lp
	authTypeSigned_lp
	authTypeSignedV2_lp
	authTypeJWT_lp
)

// Get request authentication type.
func getRequestAuthType_lp(r *http.Request) authType_lp {
	if isRequestSignatureV2_lp(r) {
		return authTypeSignedV2_lp
	} else if isRequestPresignedSignatureV2_lp(r) {
		return authTypePresignedV2_lp
	} else if isRequestSignStreamingV4_lp(r) {
		return authTypeStreamingSigned_lp
	} else if isRequestSignatureV4_lp(r) {
		return authTypeSigned_lp
	} else if isRequestPresignedSignatureV4_lp(r) {
		return authTypePresigned_lp
	} else if isRequestJWT_lp(r) {
		return authTypeJWT_lp
	} else if isRequestPostPolicySignatureV4_lp(r) {
		return authTypePostPolicy_lp
	} else if _, ok := r.Header["Authorization"]; !ok {
		return authTypeAnonymous_lp
	}
	return authTypeUnknown_lp
}

func checkRequestAuthType_lp(r *http.Request, bucket, policyAction, region string) APIErrorCode {
	fmt.Println("00000000000000000000")
	reqAuthType := getRequestAuthType_lp(r)
	switch reqAuthType {
	case authTypePresignedV2_lp, authTypeSignedV2_lp:
		// Signature V2 validation.
		s3Error := isReqAuthenticatedV2_lp(r)
		if s3Error != ErrNone {
			errorIf(errSignatureMismatch, dumpRequest(r))
		}
		return s3Error
	case authTypeSigned_lp, authTypePresigned_lp:
		s3Error := isReqAuthenticated_lp(r, region)
		if s3Error != ErrNone {
			errorIf(errSignatureMismatch, dumpRequest(r))
		}
		return s3Error
	}
	fmt.Println("AAAAAAAAAAAAAAAAAAAAA")
	if reqAuthType == authTypeAnonymous_lp && policyAction != "" {
		// http://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html
		return enforceBucketPolicy_lp(bucket, policyAction, r.URL.Path,
			r.Referer(), r.URL.Query())
	}

	// By default return ErrAccessDenied
	return ErrAccessDenied
}

// Verify if request has valid AWS Signature Version '2'.
// 关闭 v2 版签名验证
func isReqAuthenticatedV2_lp(r *http.Request) (s3Error APIErrorCode) {
	// if isRequestSignatureV2_lp(r) {
	// 	return doesSignV2Match_lp(r)
	// }
	// return doesPresignV2SignatureMatch_lp(r)
	return ErrAccessDenied
}

// 验证 v4 版签名，客户端启用
func reqSignatureV4Verify_lp(r *http.Request, region string) (s3Error APIErrorCode) {
	sha256sum := getContentSha256Cksum_lp(r)
	switch {
	case isRequestSignatureV4_lp(r):
		return doesSignatureMatch_lp(sha256sum, r, region)
	// 关闭共享 url 上传、下载
	// case isRequestPresignedSignatureV4_lp(r):
	// 	return doesPresignedSignatureMatch(sha256sum, r, region)
	default:
		return ErrAccessDenied
	}
}

// Verify if request has valid AWS Signature Version '4'.
func isReqAuthenticated_lp(r *http.Request, region string) (s3Error APIErrorCode) {
	if r == nil {
		return ErrInternalError
	}
	if errCode := reqSignatureV4Verify_lp(r, region); errCode != ErrNone {
		return errCode
	}
	payload, err := ioutil.ReadAll(r.Body)
	if err != nil {
		errorIf(err, "Unable to read request body for signature verification")
		return ErrInternalError
	}

	// Populate back the payload.
	r.Body = ioutil.NopCloser(bytes.NewReader(payload))

	// Verify Content-Md5, if payload is set.
	if r.Header.Get("Content-Md5") != "" {
		if r.Header.Get("Content-Md5") != getMD5HashBase64(payload) {
			return ErrBadDigest
		}
	}

	if skipContentSha256Cksum_lp(r) {
		return ErrNone
	}

	// Verify that X-Amz-Content-Sha256 Header == sha256(payload)
	// If X-Amz-Content-Sha256 header is not sent then we don't calculate/verify sha256(payload)
	sum := r.Header.Get("X-Amz-Content-Sha256")
	if isRequestPresignedSignatureV4_lp(r) {
		sum = r.URL.Query().Get("X-Amz-Content-Sha256")
	}
	if sum != "" && sum != getSHA256Hash(payload) {
		return ErrContentSHA256Mismatch
	}
	return ErrNone
}

// authHandler - handles all the incoming authorization headers and validates them if possible.
type authHandler_lp struct {
	handler http.Handler
}

// setAuthHandler to validate authorization header for the incoming request.
func setAuthHandler_lp(h http.Handler) http.Handler {
	return authHandler_lp{h}
}

// List of all support S3 auth types.
var supportedS3AuthTypes_lp = map[authType_lp]struct{}{
	authTypeAnonymous_lp:       {},
	authTypePresigned_lp:       {},
	authTypePresignedV2_lp:     {},
	authTypeSigned_lp:          {},
	authTypeSignedV2_lp:        {},
	authTypePostPolicy_lp:      {},
	authTypeStreamingSigned_lp: {},
}

// Validate if the authType is valid and supported.
func isSupportedS3AuthType_lp(aType authType_lp) bool {
	_, ok := supportedS3AuthTypes_lp[aType]
	return ok
}

// handler for validating incoming authorization headers.
func (a authHandler_lp) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	aType := getRequestAuthType_lp(r)
	if isSupportedS3AuthType_lp(aType) {
		// Let top level caller validate for anonymous and known signed requests.
		a.handler.ServeHTTP(w, r)
		return
	} else if aType == authTypeJWT_lp {
		// Validate Authorization header if its valid for JWT request.
		if !isHTTPRequestValid_lp(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		a.handler.ServeHTTP(w, r)
		return
	}
	writeErrorResponse(w, ErrSignatureVersionNotSupported, r.URL)
}
