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
	// "archive/zip"
	"encoding/json"
	"errors"
	"fmt"
	// "io"
	"io/ioutil"
	"net/http"
	"os"
	"path"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gorilla/mux"
	"github.com/gorilla/rpc/v2/json2"
	"github.com/minio/minio-go/pkg/policy"
	"github.com/minio/minio/browser"
)

// WebGenericArgs - empty struct for calls that don't accept arguments
// for ex. ServerInfo, GenerateAuth
type WebGenericArgs_lp struct{}

// WebGenericRep_lp - reply structure for calls for which reply is success/failure
// for ex. RemoveObject MakeBucket
type WebGenericRep_lp struct {
	UIVersion string `json:"uiVersion"`
}

// ServerInfoRep - server info reply.
type ServerInfoRep_lp struct {
	MinioVersion  string
	MinioMemory   string
	MinioPlatform string
	MinioRuntime  string
	MinioEnvVars  []string
	UIVersion     string `json:"uiVersion"`
}

// webAPI container for Web API.
type webAPIHandlers_lp struct {
	ObjectAPI func() ObjectLayer
}

// ServerInfo - get server info.
func (web *webAPIHandlers_lp) ServerInfo(r *http.Request, args *WebGenericArgs, reply *ServerInfoRep_lp) error {
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}
	host, err := os.Hostname()
	if err != nil {
		host = ""
	}
	memstats := &runtime.MemStats{}
	runtime.ReadMemStats(memstats)
	mem := fmt.Sprintf("Used: %s | Allocated: %s | Used-Heap: %s | Allocated-Heap: %s",
		humanize.Bytes(memstats.Alloc),
		humanize.Bytes(memstats.TotalAlloc),
		humanize.Bytes(memstats.HeapAlloc),
		humanize.Bytes(memstats.HeapSys))
	platform := fmt.Sprintf("Host: %s | OS: %s | Arch: %s",
		host,
		runtime.GOOS,
		runtime.GOARCH)
	goruntime := fmt.Sprintf("Version: %s | CPUs: %s", runtime.Version(), strconv.Itoa(runtime.NumCPU()))

	reply.MinioEnvVars = os.Environ()
	reply.MinioVersion = Version
	reply.MinioMemory = mem
	reply.MinioPlatform = platform
	reply.MinioRuntime = goruntime
	reply.UIVersion = browser.UIVersion
	return nil
}

// StorageInfoRep - contains storage usage statistics.
type StorageInfoRep_lp struct {
	StorageInfo StorageInfo `json:"storageInfo"`
	UIVersion   string      `json:"uiVersion"`
}

// StorageInfo - web call to gather storage usage statistics.
func (web *webAPIHandlers_lp) StorageInfo(r *http.Request, args *AuthRPCArgs, reply *StorageInfoRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}
	reply.StorageInfo = objectAPI.StorageInfo()
	reply.UIVersion = browser.UIVersion
	return nil
}

// MakeBucketArgs_lp - make bucket args.
type MakeBucketArgs_lp struct {
	BucketName string `json:"bucketName"`
}

// MakeBucket - creates a new bucket.
func (web *webAPIHandlers_lp) MakeBucket(r *http.Request, args *MakeBucketArgs_lp, reply *WebGenericRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}

	// Check if bucket is a reserved bucket name.
	if isMinioMetaBucket(args.BucketName) || isMinioReservedBucket(args.BucketName) {
		return toJSONError_lp(errReservedBucket)
	}

	bucketLock := globalNSMutex.NewNSLock(args.BucketName, "")
	bucketLock.Lock()
	defer bucketLock.Unlock()

	if err := objectAPI.MakeBucketWithLocation(args.BucketName, serverConfig.GetRegion()); err != nil {
		return toJSONError_lp(err, args.BucketName)
	}

	reply.UIVersion = browser.UIVersion
	return nil
}

// ListBucketsRep_lp - list buckets response
type ListBucketsRep_lp struct {
	Buckets   []WebBucketInfo_lp `json:"buckets"`
	UIVersion string             `json:"uiVersion"`
}

// WebBucketInfo_lp container for list buckets metadata.
type WebBucketInfo_lp struct {
	// The name of the bucket.
	Name string `json:"name"`
	// Date the bucket was created.
	CreationDate time.Time `json:"creationDate"`
}

// ListBuckets - list buckets api.
func (web *webAPIHandlers_lp) ListBuckets(r *http.Request, args *WebGenericArgs, reply *ListBucketsRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}
	authErr := webRequestAuthenticate(r)
	if authErr != nil {
		return toJSONError_lp(authErr)
	}
	buckets, err := objectAPI.ListBuckets()
	if err != nil {
		return toJSONError_lp(err)
	}
	for _, bucket := range buckets {
		reply.Buckets = append(reply.Buckets, WebBucketInfo_lp{
			Name:         bucket.Name,
			CreationDate: bucket.Created,
		})
	}
	reply.UIVersion = browser.UIVersion
	return nil
}

// ListObjectsArgs_lp - list object args.
type ListObjectsArgs_lp struct {
	BucketName string `json:"bucketName"`
	Prefix     string `json:"prefix"`
	Marker     string `json:"marker"`
}

// ListObjectsRep_lp - list objects response.
type ListObjectsRep_lp struct {
	Objects     []WebObjectInfo_lp `json:"objects"`
	NextMarker  string             `json:"nextmarker"`
	IsTruncated bool               `json:"istruncated"`
	Writable    bool               `json:"writable"` // Used by client to show "upload file" button.
	UIVersion   string             `json:"uiVersion"`
}

// WebObjectInfo_lp container for list objects metadata.
type WebObjectInfo_lp struct {
	// Name of the object
	Key string `json:"name"`
	// Date and time the object was last modified.
	LastModified time.Time `json:"lastModified"`
	// Size in bytes of the object.
	Size int64 `json:"size"`
	// ContentType is mime type of the object.
	ContentType string `json:"contentType"`
}

// ListObjects - list objects api.
func (web *webAPIHandlers_lp) ListObjects(r *http.Request, args *ListObjectsArgs_lp, reply *ListObjectsRep_lp) error {
	reply.UIVersion = browser.UIVersion
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}
	prefix := args.Prefix + "test" // To test if GetObject/PutObject with the specified prefix is allowed.
	readable := isBucketActionAllowed_lp("s3:GetObject", args.BucketName, prefix)
	writable := isBucketActionAllowed_lp("s3:PutObject", args.BucketName, prefix)
	authErr := webRequestAuthenticate(r)
	switch {
	case authErr == errAuthentication:
		return toJSONError_lp(authErr)
	case authErr == nil:
		break
	case readable && writable:
		reply.Writable = true
		break
	case readable:
		break
	case writable:
		reply.Writable = true
		return nil
	default:
		return errAuthentication
	}
	lo, err := objectAPI.ListObjects(args.BucketName, args.Prefix, args.Marker, slashSeparator, 1000)
	if err != nil {
		return &json2.Error{Message: err.Error()}
	}
	reply.NextMarker = lo.NextMarker
	reply.IsTruncated = lo.IsTruncated
	for _, obj := range lo.Objects {
		reply.Objects = append(reply.Objects, WebObjectInfo_lp{
			Key:          obj.Name,
			LastModified: obj.ModTime,
			Size:         obj.Size,
			ContentType:  obj.ContentType,
		})
	}
	for _, prefix := range lo.Prefixes {
		reply.Objects = append(reply.Objects, WebObjectInfo_lp{
			Key: prefix,
		})
	}

	return nil
}

// RemoveObjectArgs_lp - args to remove an object, JSON will look like.
//
// {
//     "bucketname": "testbucket",
//     "objects": [
//         "photos/hawaii/",
//         "photos/maldives/",
//         "photos/sanjose.jpg"
//     ]
// }
type RemoveObjectArgs_lp struct {
	Objects    []string `json:"objects"`    // Contains objects, prefixes.
	BucketName string   `json:"bucketname"` // Contains bucket name.
}

// RemoveObject - removes an object, or all the objects at a given prefix.
func (web *webAPIHandlers_lp) RemoveObject(r *http.Request, args *RemoveObjectArgs_lp, reply *WebGenericRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}

	if args.BucketName == "" || len(args.Objects) == 0 {
		return toJSONError_lp(errInvalidArgument)
	}

	var err error
next:
	for _, objectName := range args.Objects {
		// If not a directory, remove the object.
		if !hasSuffix(objectName, slashSeparator) && objectName != "" {
			if err = deleteObject(objectAPI, args.BucketName, objectName, r); err != nil {
				break next
			}
			continue
		}

		// For directories, list the contents recursively and remove.
		marker := ""
		for {
			var lo ListObjectsInfo
			lo, err = objectAPI.ListObjects(args.BucketName, objectName, marker, "", 1000)
			if err != nil {
				break next
			}
			marker = lo.NextMarker
			for _, obj := range lo.Objects {
				err = deleteObject(objectAPI, args.BucketName, obj.Name, r)
				if err != nil {
					break next
				}
			}
			if !lo.IsTruncated {
				break
			}
		}
	}

	if err != nil && !isErrObjectNotFound(err) {
		// Ignore object not found error.
		return toJSONError_lp(err, args.BucketName, "")
	}

	reply.UIVersion = browser.UIVersion
	return nil
}

// LoginArgs_lp - login arguments.
type LoginArgs_lp struct {
	Username string `json:"username" form:"username"`
	Password string `json:"password" form:"password"`
}

// LoginRep_lp - login reply.
type LoginRep_lp struct {
	Token     string `json:"token"`
	UIVersion string `json:"uiVersion"`
}

// Login - user login handler.
func (web *webAPIHandlers_lp) Login(r *http.Request, args *LoginArgs_lp, reply *LoginRep_lp) error {
	token, err := authenticateWeb_lp(args.Username, args.Password)
	if err != nil {
		// Make sure to log errors related to browser login,
		// for security and auditing reasons.
		errorIf(err, "Unable to login request from %s", r.RemoteAddr)
		return toJSONError_lp(err)
	}

	reply.Token = token
	reply.UIVersion = browser.UIVersion
	return nil
}

// GenerateAuthReply_lp - reply for GenerateAuth
type GenerateAuthReply_lp struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	UIVersion string `json:"uiVersion"`
}

func (web webAPIHandlers_lp) GenerateAuth(r *http.Request, args *WebGenericArgs, reply *GenerateAuthReply_lp) error {
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}
	cred := mustGetNewCredential()
	reply.AccessKey = cred.AccessKey
	reply.SecretKey = cred.SecretKey
	reply.UIVersion = browser.UIVersion
	return nil
}

// SetAuthArgs_lp - argument for SetAuth
type SetAuthArgs_lp struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
}

// SetAuthReply_lp - reply for SetAuth
type SetAuthReply_lp struct {
	Token       string            `json:"token"`
	UIVersion   string            `json:"uiVersion"`
	PeerErrMsgs map[string]string `json:"peerErrMsgs"`
}

// SetAuth - Set accessKey and secretKey credentials.
func (web *webAPIHandlers_lp) SetAuth(r *http.Request, args *SetAuthArgs_lp, reply *SetAuthReply_lp) error {
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}

	// If creds are set through ENV disallow changing credentials.
	if globalIsEnvCreds {
		return toJSONError_lp(errChangeCredNotAllowed)
	}

	creds, err := createCredential(args.AccessKey, args.SecretKey)
	if err != nil {
		return toJSONError_lp(err)
	}

	// Notify all other Minio peers to update credentials
	errsMap := updateCredsOnPeers(creds)

	// Update local credentials
	serverConfig.SetCredential(creds)

	// Persist updated credentials.
	if err = serverConfig.Save(); err != nil {
		errsMap[globalMinioAddr] = err
	}

	// Log all the peer related error messages, and populate the
	// PeerErrMsgs map.
	reply.PeerErrMsgs = make(map[string]string)
	for svr, errVal := range errsMap {
		tErr := fmt.Errorf("Unable to change credentials on %s: %v", svr, errVal)
		errorIf(tErr, "Credentials change could not be propagated successfully!")
		reply.PeerErrMsgs[svr] = errVal.Error()
	}

	// If we were unable to update locally, we return an error to the user/browser.
	if errsMap[globalMinioAddr] != nil {
		// Since the error message may be very long to display
		// on the browser, we tell the user to check the
		// server logs.
		return toJSONError_lp(errors.New("unexpected error(s) occurred - please check minio server logs"))
	}

	// As we have updated access/secret key, generate new auth token.
	token, err := authenticateWeb_lp(creds.AccessKey, creds.SecretKey)
	if err != nil {
		// Did we have peer errors?
		if len(errsMap) > 0 {
			err = fmt.Errorf(
				"we gave up due to: '%s', but there were more errors. Please check minio server logs",
				err.Error(),
			)
		}

		return toJSONError_lp(err)
	}

	reply.Token = token
	reply.UIVersion = browser.UIVersion
	return nil
}

// GetAuthReply_lp - Reply current credentials.
type GetAuthReply_lp struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	UIVersion string `json:"uiVersion"`
}

// GetAuth - return accessKey and secretKey credentials.
func (web *webAPIHandlers_lp) GetAuth(r *http.Request, args *WebGenericArgs, reply *GetAuthReply_lp) error {
	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}
	creds := serverConfig.GetCredential()
	reply.AccessKey = creds.AccessKey
	reply.SecretKey = creds.SecretKey
	reply.UIVersion = browser.UIVersion
	return nil
}

// Upload - file upload handler.
func (web *webAPIHandlers_lp) Upload(w http.ResponseWriter, r *http.Request) {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		writeWebErrorResponse_lp(w, errServerNotInitialized)
		return
	}

	vars := mux.Vars(r)
	bucket := vars["bucket"]
	object := vars["object"]

	authErr := webRequestAuthenticate(r)
	if authErr == errAuthentication {
		writeWebErrorResponse_lp(w, errAuthentication)
		return
	}
	if authErr != nil && !isBucketActionAllowed_lp("s3:PutObject", bucket, object) {
		writeWebErrorResponse_lp(w, errAuthentication)
		return
	}

	// Require Content-Length to be set in the request
	size := r.ContentLength
	if size < 0 {
		writeWebErrorResponse_lp(w, errSizeUnspecified)
		return
	}

	// Extract incoming metadata if any.
	metadata, err := extractMetadataFromHeader(r.Header)
	if err != nil {
		errorIf(err, "found invalid http request header")
		writeErrorResponse(w, ErrInternalError, r.URL)
		return
	}

	// Lock the object.
	objectLock := globalNSMutex.NewNSLock(bucket, object)
	objectLock.Lock()
	defer objectLock.Unlock()

	sha256sum := ""
	objInfo, err := objectAPI.PutObject(bucket, object, size, r.Body, metadata, sha256sum)
	if err != nil {
		writeWebErrorResponse_lp(w, err)
		return
	}

	// Notify object created event.
	eventNotify(eventData{
		Type:      ObjectCreatedPut,
		Bucket:    bucket,
		ObjInfo:   objInfo,
		ReqParams: extractReqParams(r),
	})
}

// Download - file download handler.
// 关闭 web 下载文件，直接返回 errAuthentication
func (web *webAPIHandlers_lp) Download(w http.ResponseWriter, r *http.Request) {
	writeWebErrorResponse_lp(w, errAuthentication)
	return

	/*	objectAPI := web.ObjectAPI()
		if objectAPI == nil {
			writeWebErrorResponse_lp(w, errServerNotInitialized)
			return
		}

		vars := mux.Vars(r)
		bucket := vars["bucket"]
		object := vars["object"]
		token := r.URL.Query().Get("token")

		if !isAuthTokenValid_lp(token) && !isBucketActionAllowed_lp("s3:GetObject", bucket, object) {
			writeWebErrorResponse_lp(w, errAuthentication)
			return
		}

		// Add content disposition.
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", path.Base(object)))

		// Lock the object before reading.
		objectLock := globalNSMutex.NewNSLock(bucket, object)
		objectLock.RLock()
		defer objectLock.RUnlock()

		if err := objectAPI.GetObject(bucket, object, 0, -1, w); err != nil {
			/// No need to print error, response writer already written to.
			return
		}*/
}

// DownloadZipArgs_lp - Argument for downloading a bunch of files as a zip file.
// JSON will look like:
// '{"bucketname":"testbucket","prefix":"john/pics/","objects":["hawaii/","maldives/","sanjose.jpg"]}'
type DownloadZipArgs_lp struct {
	Objects    []string `json:"objects"`    // can be files or sub-directories
	Prefix     string   `json:"prefix"`     // current directory in the browser-ui
	BucketName string   `json:"bucketname"` // bucket name.
}

// Takes a list of objects and creates a zip file that sent as the response body.
// 关闭zip打包下载，直接返回 errAuthentication
func (web *webAPIHandlers_lp) DownloadZip(w http.ResponseWriter, r *http.Request) {
	writeWebErrorResponse_lp(w, errAuthentication)
	return

	/*objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		writeWebErrorResponse_lp(w, errServerNotInitialized)
		return
	}

	// Auth is done after reading the body to accommodate for anonymous requests
	// when bucket policy is enabled.
	var args DownloadZipArgs_lp
	tenKB := 10 * 1024 // To limit r.Body to take care of misbehaving anonymous client.
	decodeErr := json.NewDecoder(io.LimitReader(r.Body, int64(tenKB))).Decode(&args)
	if decodeErr != nil {
		writeWebErrorResponse_lp(w, decodeErr)
		return
	}

	token := r.URL.Query().Get("token")
	if !isAuthTokenValid_lp(token) {
		for _, object := range args.Objects {
			if !isBucketActionAllowed_lp("s3:GetObject", args.BucketName, pathJoin(args.Prefix, object)) {
				writeWebErrorResponse_lp(w, errAuthentication)
				return
			}
		}
	}

	archive := zip.NewWriter(w)
	defer archive.Close()

	for _, object := range args.Objects {
		// Writes compressed object file to the response.
		zipit := func(objectName string) error {
			info, err := objectAPI.GetObjectInfo(args.BucketName, objectName)
			if err != nil {
				return err
			}
			header := &zip.FileHeader{
				Name:               strings.TrimPrefix(objectName, args.Prefix),
				Method:             zip.Deflate,
				UncompressedSize64: uint64(info.Size),
				UncompressedSize:   uint32(info.Size),
			}
			writer, err := archive.CreateHeader(header)
			if err != nil {
				writeWebErrorResponse_lp(w, errUnexpected)
				return err
			}
			return objectAPI.GetObject(args.BucketName, objectName, 0, info.Size, writer)
		}

		if !hasSuffix(object, slashSeparator) {
			// If not a directory, compress the file and write it to response.
			err := zipit(pathJoin(args.Prefix, object))
			if err != nil {
				return
			}
			continue
		}

		// For directories, list the contents recursively and write the objects as compressed
		// date to the response writer.
		marker := ""
		for {
			lo, err := objectAPI.ListObjects(args.BucketName, pathJoin(args.Prefix, object), marker, "", 1000)
			if err != nil {
				return
			}
			marker = lo.NextMarker
			for _, obj := range lo.Objects {
				err = zipit(obj.Name)
				if err != nil {
					return
				}
			}
			if !lo.IsTruncated {
				break
			}
		}
	}*/
}

// GetBucketPolicyArgs_lp - get bucket policy args.
type GetBucketPolicyArgs_lp struct {
	BucketName string `json:"bucketName"`
	Prefix     string `json:"prefix"`
}

// GetBucketPolicyRep_lp - get bucket policy reply.
type GetBucketPolicyRep_lp struct {
	UIVersion string              `json:"uiVersion"`
	Policy    policy.BucketPolicy `json:"policy"`
}

func readBucketAccessPolicy_lp(objAPI ObjectLayer, bucketName string) (policy.BucketAccessPolicy, error) {
	bucketPolicyReader, err := readBucketPolicyJSON(bucketName, objAPI)
	if err != nil {
		if _, ok := err.(BucketPolicyNotFound); ok {
			return policy.BucketAccessPolicy{Version: "2012-10-17"}, nil
		}
		return policy.BucketAccessPolicy{}, err
	}

	bucketPolicyBuf, err := ioutil.ReadAll(bucketPolicyReader)
	if err != nil {
		return policy.BucketAccessPolicy{}, err
	}

	policyInfo := policy.BucketAccessPolicy{}
	err = json.Unmarshal(bucketPolicyBuf, &policyInfo)
	if err != nil {
		return policy.BucketAccessPolicy{}, err
	}

	return policyInfo, nil

}

// GetBucketPolicy - get bucket policy.
func (web *webAPIHandlers_lp) GetBucketPolicy(r *http.Request, args *GetBucketPolicyArgs_lp, reply *GetBucketPolicyRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}

	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}

	policyInfo, err := readBucketAccessPolicy_lp(objectAPI, args.BucketName)
	if err != nil {
		return toJSONError_lp(err, args.BucketName)
	}

	reply.UIVersion = browser.UIVersion
	reply.Policy = policy.GetPolicy(policyInfo.Statements, args.BucketName, args.Prefix)

	return nil
}

// ListAllBucketPoliciesArgs_lp - get all bucket policies.
type ListAllBucketPoliciesArgs_lp struct {
	BucketName string `json:"bucketName"`
}

// BucketAccessPolicy_lp - Collection of canned bucket policy at a given prefix.
type BucketAccessPolicy_lp struct {
	Prefix string              `json:"prefix"`
	Policy policy.BucketPolicy `json:"policy"`
}

// ListAllBucketPoliciesRep_lp - get all bucket policy reply.
type ListAllBucketPoliciesRep_lp struct {
	UIVersion string                  `json:"uiVersion"`
	Policies  []BucketAccessPolicy_lp `json:"policies"`
}

// GetllBucketPolicy - get all bucket policy.
func (web *webAPIHandlers_lp) ListAllBucketPolicies(r *http.Request, args *ListAllBucketPoliciesArgs_lp, reply *ListAllBucketPoliciesRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}

	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}

	policyInfo, err := readBucketAccessPolicy_lp(objectAPI, args.BucketName)
	if err != nil {
		return toJSONError_lp(err, args.BucketName)
	}

	reply.UIVersion = browser.UIVersion
	for prefix, policy := range policy.GetPolicies(policyInfo.Statements, args.BucketName) {
		reply.Policies = append(reply.Policies, BucketAccessPolicy_lp{
			Prefix: prefix,
			Policy: policy,
		})
	}
	return nil
}

// SetBucketPolicyArgs_lp - set bucket policy args.
type SetBucketPolicyArgs_lp struct {
	BucketName string `json:"bucketName"`
	Prefix     string `json:"prefix"`
	Policy     string `json:"policy"`
}

// SetBucketPolicy - set bucket policy.
func (web *webAPIHandlers_lp) SetBucketPolicy(r *http.Request, args *SetBucketPolicyArgs_lp, reply *WebGenericRep_lp) error {
	objectAPI := web.ObjectAPI()
	if objectAPI == nil {
		return toJSONError_lp(errServerNotInitialized)
	}

	if !isHTTPRequestValid(r) {
		return toJSONError_lp(errAuthentication)
	}

	bucketP := policy.BucketPolicy(args.Policy)
	if !bucketP.IsValidBucketPolicy() {
		return &json2.Error{
			Message: "Invalid policy type " + args.Policy,
		}
	}

	policyInfo, err := readBucketAccessPolicy_lp(objectAPI, args.BucketName)
	if err != nil {
		return toJSONError_lp(err, args.BucketName)
	}
	policyInfo.Statements = policy.SetPolicy(policyInfo.Statements, bucketP, args.BucketName, args.Prefix)
	if len(policyInfo.Statements) == 0 {
		err = persistAndNotifyBucketPolicyChange(args.BucketName, policyChange{true, nil}, objectAPI)
		if err != nil {
			return toJSONError_lp(err, args.BucketName)
		}
		reply.UIVersion = browser.UIVersion
		return nil
	}
	data, err := json.Marshal(policyInfo)
	if err != nil {
		return toJSONError_lp(err)
	}

	// Parse validate and save bucket policy.
	if s3Error := parseAndPersistBucketPolicy(args.BucketName, data, objectAPI); s3Error != ErrNone {
		apiErr := getAPIError(s3Error)
		var err error
		if apiErr.Code == "XMinioPolicyNesting" {
			err = PolicyNesting{}
		} else {
			err = errors.New(apiErr.Description)
		}
		return toJSONError_lp(err, args.BucketName)
	}
	reply.UIVersion = browser.UIVersion
	return nil
}

// PresignedGetArgs_lp - presigned-get API args.
type PresignedGetArgs_lp struct {
	// Host header required for signed headers.
	HostName string `json:"host"`

	// Bucket name of the object to be presigned.
	BucketName string `json:"bucket"`

	// Object name to be presigned.
	ObjectName string `json:"object"`

	// Expiry in seconds.
	Expiry int64 `json:"expiry"`
}

// PresignedGetRep_lp - presigned-get URL reply.
type PresignedGetRep_lp struct {
	UIVersion string `json:"uiVersion"`
	// Presigned URL of the object.
	URL string `json:"url"`
}

// PresignedGET - returns presigned-Get url.
// 关闭网页生成上传下载链接功能，客户端生成链接的无法屏蔽，但是可以在 auth-handler.go 中关闭 Presign 相关的验证
func (web *webAPIHandlers_lp) PresignedGet(r *http.Request, args *PresignedGetArgs_lp, reply *PresignedGetRep_lp) error {
	// if !isHTTPRequestValid(r) {
	return toJSONError_lp(errAuthentication)
	// }

	if args.BucketName == "" || args.ObjectName == "" {
		return &json2.Error{
			Message: "Bucket and Object are mandatory arguments.",
		}
	}
	reply.UIVersion = browser.UIVersion
	reply.URL = presignedGet_lp(args.HostName, args.BucketName, args.ObjectName, args.Expiry)
	return nil
}

// Returns presigned url for GET method.
func presignedGet_lp(host, bucket, object string, expiry int64) string {
	cred := serverConfig.GetCredential()
	region := serverConfig.GetRegion()

	accessKey := cred.AccessKey
	secretKey := cred.SecretKey

	date := UTCNow()
	dateStr := date.Format(iso8601Format)
	credential := fmt.Sprintf("%s/%s", accessKey, getScope(date, region))

	var expiryStr = "604800" // Default set to be expire in 7days.
	if expiry < 604800 && expiry > 0 {
		expiryStr = strconv.FormatInt(expiry, 10)
	}
	query := strings.Join([]string{
		"X-Amz-Algorithm=" + signV4Algorithm,
		"X-Amz-Credential=" + strings.Replace(credential, "/", "%2F", -1),
		"X-Amz-Date=" + dateStr,
		"X-Amz-Expires=" + expiryStr,
		"X-Amz-SignedHeaders=host",
	}, "&")

	path := "/" + path.Join(bucket, object)

	// "host" is the only header required to be signed for Presigned URLs.
	extractedSignedHeaders := make(http.Header)
	extractedSignedHeaders.Set("host", host)
	canonicalRequest := getCanonicalRequest(extractedSignedHeaders, unsignedPayload, query, path, "GET")
	stringToSign := getStringToSign(canonicalRequest, date, getScope(date, region))
	signingKey := getSigningKey(secretKey, date, region)
	signature := getSignature(signingKey, stringToSign)

	// Construct the final presigned URL.
	return host + path + "?" + query + "&" + "X-Amz-Signature=" + signature
}

// toJSONError_lp converts regular errors into more user friendly
// and consumable error message for the browser UI.
func toJSONError_lp(err error, params ...string) (jerr *json2.Error) {
	apiErr := toWebAPIError_lp(err)
	jerr = &json2.Error{
		Message: apiErr.Description,
	}
	switch apiErr.Code {
	// Reserved bucket name provided.
	case "AllAccessDisabled":
		if len(params) > 0 {
			jerr = &json2.Error{
				Message: fmt.Sprintf("All access to this bucket %s has been disabled.", params[0]),
			}
		}
	// Bucket name invalid with custom error message.
	case "InvalidBucketName":
		if len(params) > 0 {
			jerr = &json2.Error{
				Message: fmt.Sprintf("Bucket Name %s is invalid. Lowercase letters, period, numerals are the only allowed characters and should be minimum 3 characters in length.", params[0]),
			}
		}
	// Bucket not found custom error message.
	case "NoSuchBucket":
		if len(params) > 0 {
			jerr = &json2.Error{
				Message: fmt.Sprintf("The specified bucket %s does not exist.", params[0]),
			}
		}
	// Object not found custom error message.
	case "NoSuchKey":
		if len(params) > 1 {
			jerr = &json2.Error{
				Message: fmt.Sprintf("The specified key %s does not exist", params[1]),
			}
		}
		// Add more custom error messages here with more context.
	}
	return jerr
}

// toWebAPIError_lp - convert into error into APIError.
func toWebAPIError_lp(err error) APIError {
	err = errorCause(err)
	if err == errAuthentication {
		return APIError{
			Code:           "AccessDenied",
			HTTPStatusCode: http.StatusForbidden,
			Description:    err.Error(),
		}
	} else if err == errServerNotInitialized {
		return APIError{
			Code:           "XMinioServerNotInitialized",
			HTTPStatusCode: http.StatusServiceUnavailable,
			Description:    err.Error(),
		}
	} else if err == errInvalidAccessKeyLength {
		return APIError{
			Code:           "AccessDenied",
			HTTPStatusCode: http.StatusForbidden,
			Description:    err.Error(),
		}
	} else if err == errInvalidSecretKeyLength {
		return APIError{
			Code:           "AccessDenied",
			HTTPStatusCode: http.StatusForbidden,
			Description:    err.Error(),
		}
	} else if err == errInvalidAccessKeyID {
		return APIError{
			Code:           "AccessDenied",
			HTTPStatusCode: http.StatusForbidden,
			Description:    err.Error(),
		}
	} else if err == errSizeUnspecified {
		return APIError{
			Code:           "InvalidRequest",
			HTTPStatusCode: http.StatusBadRequest,
			Description:    err.Error(),
		}
	} else if err == errChangeCredNotAllowed {
		return APIError{
			Code:           "MethodNotAllowed",
			HTTPStatusCode: http.StatusMethodNotAllowed,
			Description:    err.Error(),
		}
	} else if err == errReservedBucket {
		return APIError{
			Code:           "AllAccessDisabled",
			HTTPStatusCode: http.StatusForbidden,
			Description:    err.Error(),
		}
	} else if err == errInvalidArgument {
		return APIError{
			Code:           "InvalidArgument",
			HTTPStatusCode: http.StatusBadRequest,
			Description:    err.Error(),
		}
	}
	// Convert error type to api error code.
	var apiErrCode APIErrorCode
	switch err.(type) {
	case StorageFull:
		apiErrCode = ErrStorageFull
	case BucketNotFound:
		apiErrCode = ErrNoSuchBucket
	case BucketExists:
		apiErrCode = ErrBucketAlreadyOwnedByYou
	case BucketNameInvalid:
		apiErrCode = ErrInvalidBucketName
	case BadDigest:
		apiErrCode = ErrBadDigest
	case IncompleteBody:
		apiErrCode = ErrIncompleteBody
	case ObjectExistsAsDirectory:
		apiErrCode = ErrObjectExistsAsDirectory
	case ObjectNotFound:
		apiErrCode = ErrNoSuchKey
	case ObjectNameInvalid:
		apiErrCode = ErrNoSuchKey
	case InsufficientWriteQuorum:
		apiErrCode = ErrWriteQuorum
	case InsufficientReadQuorum:
		apiErrCode = ErrReadQuorum
	case PolicyNesting:
		apiErrCode = ErrPolicyNesting
	default:
		// Log unexpected and unhandled errors.
		errorIf(err, errUnexpected.Error())
		apiErrCode = ErrInternalError
	}
	apiErr := getAPIError(apiErrCode)
	return apiErr
}

// writeWebErrorResponse_lp - set HTTP status code and write error description to the body.
func writeWebErrorResponse_lp(w http.ResponseWriter, err error) {
	apiErr := toWebAPIError_lp(err)
	w.WriteHeader(apiErr.HTTPStatusCode)
	w.Write([]byte(apiErr.Description))
}