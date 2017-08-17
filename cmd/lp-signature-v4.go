/*
 * Minio Cloud Storage, (C) 2015, 2016, 2017 Minio, Inc.
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

// Package cmd This file implements helper functions to validate AWS
// Signature Version '4' authorization header.
//
// This package provides comprehensive helpers for following signature
// types.
// - Based on Authorization header.
// - Based on Query parameters.
// - Based on Form POST policy.
package cmd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/sha256-simd"
	"github.com/ory-am/ladon"
)

// AWS Signature Version '4' constants.
const (
	signV4Algorithm_lp     = "AWS4-HMAC-SHA256"
	iso8601Format_lp       = "20060102T150405Z"
	yyyymmdd_lp            = "20060102"
	presignedHostHeader_lp = "host"
)

// getCanonicalHeaders generate a list of request headers with their values
func getCanonicalHeaders_lp(signedHeaders http.Header) string {
	var headers []string
	vals := make(http.Header)
	for k, vv := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
		vals[strings.ToLower(k)] = vv
	}
	sort.Strings(headers)

	var buf bytes.Buffer
	for _, k := range headers {
		buf.WriteString(k)
		buf.WriteByte(':')
		for idx, v := range vals[k] {
			if idx > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(signV4TrimAll_lp(v))
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

// getSignedHeaders generate a string i.e alphabetically sorted, semicolon-separated list of lowercase request header names
func getSignedHeaders_lp(signedHeaders http.Header) string {
	var headers []string
	for k := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

// getCanonicalRequest generate a canonical request of style
//
// canonicalRequest =
//  <HTTPMethod>\n
//  <CanonicalURI>\n
//  <CanonicalQueryString>\n
//  <CanonicalHeaders>\n
//  <SignedHeaders>\n
//  <HashedPayload>
//
func getCanonicalRequest_lp(extractedSignedHeaders http.Header, payload, queryStr, urlPath, method string) string {
	rawQuery := strings.Replace(queryStr, "+", "%20", -1)
	encodedPath := getURLEncodedName_lp(urlPath)
	canonicalRequest := strings.Join([]string{
		method,
		encodedPath,
		rawQuery,
		getCanonicalHeaders_lp(extractedSignedHeaders),
		getSignedHeaders_lp(extractedSignedHeaders),
		payload,
	}, "\n")
	return canonicalRequest
}

// getScope generate a string of a specific date, an AWS region, and a service.
func getScope_lp(t time.Time, region string) string {
	scope := strings.Join([]string{
		t.Format(yyyymmdd),
		region,
		"s3",
		"aws4_request",
	}, "/")
	return scope
}

// getStringToSign a string based on selected query values.
func getStringToSign_lp(canonicalRequest string, t time.Time, scope string) string {
	stringToSign := signV4Algorithm + "\n" + t.Format(iso8601Format) + "\n"
	stringToSign = stringToSign + scope + "\n"
	canonicalRequestBytes := sha256.Sum256([]byte(canonicalRequest))
	stringToSign = stringToSign + hex.EncodeToString(canonicalRequestBytes[:])
	return stringToSign
}

// getSigningKey hmac seed to calculate final signature.
func getSigningKey_lp(secretKey string, t time.Time, region string) []byte {
	date := sumHMAC_lp([]byte("AWS4"+secretKey), []byte(t.Format(yyyymmdd)))
	regionBytes := sumHMAC_lp(date, []byte(region))
	service := sumHMAC_lp(regionBytes, []byte("s3"))
	signingKey := sumHMAC_lp(service, []byte("aws4_request"))
	return signingKey
}

// getSignature final signature in hexadecimal form.
func getSignature_lp(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC_lp(signingKey, []byte(stringToSign)))
}

// Check to see if Policy is signed correctly.
func doesPolicySignatureMatch_lp(formValues http.Header) APIErrorCode {
	// For SignV2 - Signature field will be valid
	if _, ok := formValues["Signature"]; ok {
		return doesPolicySignatureV2Match_lp(formValues)
	}
	return doesPolicySignatureV4Match_lp(formValues)
}

// doesPolicySignatureMatch - Verify query headers with post policy
//     - http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
// returns ErrNone if the signature matches.
func doesPolicySignatureV4Match_lp(formValues http.Header) APIErrorCode {
	// Access credentials.
	cred := serverConfig.GetCredential()

	// Server region.
	region := serverConfig.GetRegion()

	// Parse credential tag.
	credHeader, err := parseCredentialHeader_lp("Credential=" + formValues.Get("X-Amz-Credential"))
	if err != ErrNone {
		return ErrMissingFields
	}

	// Verify if the access key id matches.
	if credHeader.accessKey != cred.AccessKey {
		// 调用 GetCredential_lp 获取指定租户的凭证
		cred = GetCredential_lp(credHeader.accessKey)
		// return ErrInvalidAccessKeyID
	}

	// Verify if the region is valid.
	sRegion := credHeader.scope.region
	if !isValidRegion_lp(sRegion, region) {
		return ErrInvalidRegion
	}

	// Get signing key.
	signingKey := getSigningKey_lp(cred.SecretKey, credHeader.scope.date, sRegion)

	// Get signature.
	newSignature := getSignature_lp(signingKey, formValues.Get("Policy"))

	// Verify signature.
	if newSignature != formValues.Get("X-Amz-Signature") {
		return ErrSignatureDoesNotMatch
	}

	// Success.
	return ErrNone
}

// doesPresignedSignatureMatch - Verify query headers with presigned signature
//     - http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
// returns ErrNone if the signature matches.
func doesPresignedSignatureMatch_lp(hashedPayload string, r *http.Request, region string) APIErrorCode {
	// Access credentials.
	cred := serverConfig.GetCredential()

	// Copy request
	req := *r

	// Parse request query string.
	pSignValues, err := parsePreSignV4_lp(req.URL.Query())
	if err != ErrNone {
		return err
	}

	// Verify if the access key id matches.
	if pSignValues.Credential.accessKey != cred.AccessKey {
		// 调用 GetCredential_lp 获取指定租户的凭证
		cred = GetCredential_lp(pSignValues.Credential.accessKey)
		// return ErrInvalidAccessKeyID
	}

	// Verify if region is valid.
	sRegion := pSignValues.Credential.scope.region
	// Should validate region, only if region is set.
	if region == "" {
		region = sRegion
	}
	if !isValidRegion_lp(sRegion, region) {
		return ErrInvalidRegion
	}

	// Extract all the signed headers along with its values.
	extractedSignedHeaders, errCode := extractSignedHeaders_lp(pSignValues.SignedHeaders, r)
	if errCode != ErrNone {
		return errCode
	}
	// Construct new query.
	query := make(url.Values)
	if req.URL.Query().Get("X-Amz-Content-Sha256") != "" {
		query.Set("X-Amz-Content-Sha256", hashedPayload)
	}

	query.Set("X-Amz-Algorithm", signV4Algorithm)

	// If the host which signed the request is slightly ahead in time (by less than globalMaxSkewTime) the
	// request should still be allowed.
	if pSignValues.Date.After(UTCNow().Add(globalMaxSkewTime)) {
		return ErrRequestNotReadyYet
	}

	if UTCNow().Sub(pSignValues.Date) > time.Duration(pSignValues.Expires) {
		return ErrExpiredPresignRequest
	}

	// Save the date and expires.
	t := pSignValues.Date
	expireSeconds := int(time.Duration(pSignValues.Expires) / time.Second)

	// Construct the query.
	query.Set("X-Amz-Date", t.Format(iso8601Format))
	query.Set("X-Amz-Expires", strconv.Itoa(expireSeconds))
	query.Set("X-Amz-SignedHeaders", getSignedHeaders(extractedSignedHeaders))
	query.Set("X-Amz-Credential", cred.AccessKey+"/"+getScope(t, sRegion))

	// Save other headers available in the request parameters.
	for k, v := range req.URL.Query() {
		if strings.HasPrefix(strings.ToLower(k), "x-amz") {
			continue
		}
		query[k] = v
	}

	// Get the encoded query.
	encodedQuery := query.Encode()

	// Verify if date query is same.
	if req.URL.Query().Get("X-Amz-Date") != query.Get("X-Amz-Date") {
		return ErrSignatureDoesNotMatch
	}
	// Verify if expires query is same.
	if req.URL.Query().Get("X-Amz-Expires") != query.Get("X-Amz-Expires") {
		return ErrSignatureDoesNotMatch
	}
	// Verify if signed headers query is same.
	if req.URL.Query().Get("X-Amz-SignedHeaders") != query.Get("X-Amz-SignedHeaders") {
		return ErrSignatureDoesNotMatch
	}
	// Verify if credential query is same.
	if req.URL.Query().Get("X-Amz-Credential") != query.Get("X-Amz-Credential") {
		return ErrSignatureDoesNotMatch
	}
	// Verify if sha256 payload query is same.
	if req.URL.Query().Get("X-Amz-Content-Sha256") != "" {
		if req.URL.Query().Get("X-Amz-Content-Sha256") != query.Get("X-Amz-Content-Sha256") {
			return ErrSignatureDoesNotMatch
		}
	}

	/// Verify finally if signature is same.

	// Get canonical request.
	presignedCanonicalReq := getCanonicalRequest_lp(extractedSignedHeaders, hashedPayload, encodedQuery, req.URL.Path, req.Method)

	// Get string to sign from canonical request.
	presignedStringToSign := getStringToSign_lp(presignedCanonicalReq, t, pSignValues.Credential.getScope())

	// Get hmac presigned signing key.
	presignedSigningKey := getSigningKey_lp(cred.SecretKey, pSignValues.Credential.scope.date, region)

	// Get new signature.
	newSignature := getSignature_lp(presignedSigningKey, presignedStringToSign)

	// Verify signature.
	if req.URL.Query().Get("X-Amz-Signature") != newSignature {
		return ErrSignatureDoesNotMatch
	}

	// TODO: ladon 鉴权
	fmt.Println("presigned", encodedQuery, req.URL.Path, req.Method)

	return ErrNone
}

// doesSignatureMatch - Verify authorization header with calculated header in accordance with
//     - http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
// returns ErrNone if signature matches.
// V4 版 验证签名的方法，如果成功，则返回空
func doesSignatureMatch_lp(hashedPayload string, r *http.Request, region string) APIErrorCode {
	// Access credentials.
	cred := serverConfig.GetCredential()

	// Copy request.
	req := *r

	// Save authorization header.
	v4Auth := req.Header.Get("Authorization")

	// Parse signature version '4' header.
	signV4Values, err := parseSignV4(v4Auth)
	if err != ErrNone {
		return err
	}

	// Extract all the signed headers along with its values.
	extractedSignedHeaders, errCode := extractSignedHeaders_lp(signV4Values.SignedHeaders, r)
	if errCode != ErrNone {
		return errCode
	}

	// Verify if the access key id matches.
	if signV4Values.Credential.accessKey != cred.AccessKey {
		// 调用 GetCredential_lp 获取指定租户的凭证
		cred = GetCredential_lp(signV4Values.Credential.accessKey)
		// return ErrInvalidAccessKeyID
	}

	// Verify if region is valid.
	sRegion := signV4Values.Credential.scope.region
	// Region is set to be empty, we use whatever was sent by the
	// request and proceed further. This is a work-around to address
	// an important problem for ListBuckets() getting signed with
	// different regions.
	if region == "" {
		region = sRegion
	}
	// Should validate region, only if region is set.
	if !isValidRegion_lp(sRegion, region) {
		return ErrInvalidRegion
	}

	// Extract date, if not present throw error.
	var date string
	if date = req.Header.Get(http.CanonicalHeaderKey("x-amz-date")); date == "" {
		if date = r.Header.Get("Date"); date == "" {
			return ErrMissingDateHeader
		}
	}
	// Parse date header.
	t, e := time.Parse(iso8601Format, date)
	if e != nil {
		return ErrMalformedDate
	}

	// Query string.
	queryStr := req.URL.Query().Encode()

	// Get canonical request.
	canonicalRequest := getCanonicalRequest_lp(extractedSignedHeaders, hashedPayload, queryStr, req.URL.Path, req.Method)

	// Get string to sign from canonical request.
	stringToSign := getStringToSign_lp(canonicalRequest, t, signV4Values.Credential.getScope())

	// Get hmac signing key.
	signingKey := getSigningKey_lp(cred.SecretKey, signV4Values.Credential.scope.date, region)

	// Calculate signature.
	newSignature := getSignature_lp(signingKey, stringToSign)

	// Verify if signature match.
	if newSignature != signV4Values.Signature {
		return ErrSignatureDoesNotMatch
	}

	// TODO: ladon 鉴权
	fmt.Println("signed", signV4Values, region, queryStr, req.URL.Path, req.Method)
	ladonReq := ladon.Request{
		Resource: req.URL.Path,
		Action:   req.Method,
		Subject:  signV4Values.Credential.accessKey,
		Context: ladon.Context{
			"owner": signV4Values.Credential.accessKey,
			"cidr":  getSourceIPAddress(r),
		},
	}
	if err := isAllowd(&ladonReq); err != nil {
		return ErrAccessDenied
	}
	// Return error none.
	return ErrNone
}
