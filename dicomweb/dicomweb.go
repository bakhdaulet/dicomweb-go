package dicomweb

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/philippfranke/multipart-related/related"
)

// Client defines the client for connecting to dicom server.
// For the naming of the member function such as Query, Retrieve, etc., see
// https://www.dicomstandard.org/wp-content/uploads/2018/04/DICOMweb-Cheatsheet.pdf
// for more detail.
type Client struct {
	httpClient     *http.Client
	qidoEndpoint   string
	wadoEndpoint   string
	stowEndpoint   string
	authorization  string
	clientId       string
	secret         string
	tenantId       string
	boundary       string
	accessToken    string
	expirationTime time.Time
	cacheMutex     sync.RWMutex
	optionFuncs    *[]OptionFunc
}

// OptionFunc is a signature for methods which can modify dicom requests
// before they are executed. And example would be to inject custom HTTP headers
type OptionFunc func(*http.Request) error

// ClientOption specifies the option for the DICOMweb client.
type ClientOption struct {
	// QIDOEndpoint endpoint for QIDO.
	QIDOEndpoint string
	// WADOEndpoint endpoint for WADO.
	WADOEndpoint string
	// STOWEndpoint endpoint for STOW.
	STOWEndpoint string
	// HTTPClient to perform requests. Uses http.DefaultClient otherwise
	HTTPClient *http.Client
	// OptionFuncs is an array of OptionFunc which are called before each request
	OptionFuncs *[]OptionFunc
}

// WithAuthentication configures the client.
func (c *Client) WithAuthentication(auth string) *Client {
	data := []byte(auth)
	authStr := "Basic " + base64.StdEncoding.EncodeToString(data)
	c.authorization = authStr
	return c
}

func (c *Client) getAccessToken() error {
	c.cacheMutex.RLock()
	if c.accessToken != "" && c.expirationTime.After(time.Now()) {
		defer c.cacheMutex.RUnlock()
		authStr := "Bearer " + c.accessToken
		c.authorization = authStr
		return nil
	}
	c.cacheMutex.RUnlock()

	// If the cached token is expired or not present, request a new one
	c.cacheMutex.Lock()
	defer c.cacheMutex.Unlock()

	// Check again in case another goroutine has updated the token while this one was waiting for the lock
	if c.accessToken != "" && c.expirationTime.After(time.Now()) {
		authStr := "Bearer " + c.accessToken
		c.authorization = authStr
		return nil
	}

	url := "https://login.microsoftonline.com/" + c.tenantId + "/oauth2/token"
	method := "POST"

	payload := strings.NewReader("grant_type=client_credentials&client_id=" + c.clientId + "&client_secret=" + c.secret + "&resource=https://dicom.healthcareapis.azure.com")

	client := &http.Client{}
	req, err := http.NewRequest(method, url, payload)
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	var response map[string]interface{}
	err = json.Unmarshal(body, &response)
	if err != nil {
		return err
	}

	newAccessToken, ok := response["access_token"].(string)
	if !ok {
		return fmt.Errorf("access token not found in response")
	}

	expiresIn, err := time.ParseDuration(response["expires_in"].(string) + "s")
	if err != nil {
		return err
	}

	c.accessToken = newAccessToken
	c.expirationTime = time.Now().Add(expiresIn)
	authStr := "Bearer " + c.accessToken
	c.authorization = authStr
	return nil
}

// WithAuthentication configures the client.
func (c *Client) WithAuthenticationClientSecret(clientId, secret, tenantid string) *Client {
	c.clientId = clientId
	c.secret = secret
	c.tenantId = tenantid
	return c
}

// WithInsecure create a http client that skip verifying, do not use it in production.
func (c *Client) WithInsecure() *Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}
	c.httpClient = client
	return c
}

// NewClient creates a new client.
func NewClient(option ClientOption) *Client {
	httpClient := http.DefaultClient
	if option.HTTPClient != nil {
		httpClient = option.HTTPClient
	}
	return &Client{
		httpClient:   httpClient,
		optionFuncs:  option.OptionFuncs,
		qidoEndpoint: option.QIDOEndpoint,
		wadoEndpoint: option.WADOEndpoint,
		stowEndpoint: option.STOWEndpoint,
		boundary:     "dicomwebgoWxkTrZ",
	}
}

// Query based on QIDO, query a list of either matched studies, series or instances.
func (c *Client) Query(req QIDORequest) ([]QIDOResponse, error) {
	url := c.qidoEndpoint
	switch req.Type {
	case Study:
		url += "/studies"
	case Series:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series"
	case Instance:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/instances"
	default:
		return nil, errors.New("failed to query: need to specify query type")
	}

	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	mp := map[string]interface{}{}
	databytes, _ := json.Marshal(req)
	json.Unmarshal(databytes, &mp)

	for k, v := range mp {
		if k == "Type" || k == "0020000D" || k == "0020000E" || k == "00080018" {
			continue
		}
		switch t := v.(type) {
		case float64:
			q.Add(k, fmt.Sprintf("%.0f", t))
		case string:
			q.Add(k, t)
		}
	}

	r.URL.RawQuery = q.Encode()
	if c.clientId != "" {
		err = c.getAccessToken()
		if err != nil {
			return nil, err
		}
	}
	if c.authorization != "" {
		r.Header.Set("Authorization", c.authorization)
	}
	if c.optionFuncs != nil {
		for _, fn := range *c.optionFuncs {
			if fn == nil {
				continue
			}
			if err := fn(r); err != nil {
				return nil, err
			}
		}
	}
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return nil, errors.New(resp.Status)
	}

	result := []QIDOResponse{}
	json.NewDecoder(resp.Body).Decode(&result)
	return result, nil
}

// Retrieve based on WADO, retrieve the DICOM image of given id.
func (c *Client) Retrieve(req WADORequest) ([][]byte, error) {
	if ok := req.Validate(); !ok {
		return nil, errors.New("parameters does not match the given type")
	}

	url := c.wadoEndpoint

	switch req.Type {
	case StudyRaw:
		url += "/studies/" + req.StudyInstanceUID
	case StudyRendered:
		url += "/studies/" + req.StudyInstanceUID
		url += "/rendered"
	case SeriesRaw:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
	case SeriesRendered:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/rendered"
	case SeriesMetadata:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/metadata"
	case InstanceRaw:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/instances/" + req.SOPInstanceUID
	case InstanceRendered:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/instances/" + req.SOPInstanceUID
		url += "/rendered"
	case InstanceMetadata:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/instances/" + req.SOPInstanceUID
		url += "/metadata"
	case Frame:
		url += "/studies/" + req.StudyInstanceUID
		url += "/series/" + req.SeriesInstanceUID
		url += "/instances/" + req.SOPInstanceUID
		url += "/frames/" + strconv.Itoa(req.FrameID)
	case URIReference:
		url = req.RetrieveURL
	}

	r, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if c.authorization != "" {
		r.Header.Set("Authorization", c.authorization)
	}
	if c.optionFuncs != nil {
		for _, fn := range *c.optionFuncs {
			if fn == nil {
				continue
			}
			if err := fn(r); err != nil {
				return nil, err
			}
		}
	}
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		// b, _ := ioutil.ReadAll(resp.Body)
		return nil, errors.New(resp.Status)
	}

	parts := [][]byte{}
	mediaType, params, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(mediaType, "multipart/") {
		return nil, errors.New("unexpected Content-Type, should be multipart/related")
	}

	if params["start"] == "" {
		mr := multipart.NewReader(resp.Body, params["boundary"])
		for {
			p, err := mr.NextPart()
			if err == io.EOF {
				return parts, nil
			} else if err != nil {
				log.Fatalf("failed to read next multipart: %v", err)
				return nil, err
			}

			data, err := ioutil.ReadAll(p)
			if err != nil {
				log.Fatalf("failed to read multipart response: %v", err)
				return nil, err
			}
			parts = append(parts, data)
		}
	} else {
		r := related.NewReader(resp.Body, params)
		obj, err := r.ReadObject()
		if err != nil {
			return nil, err
		}
		for _, part := range obj.Values {
			data, err := ioutil.ReadAll(part)
			if err != nil {
				return nil, err
			}
			parts = append(parts, data)
		}
	}

	return parts, nil
}

// Store based on STOW, store the DICOM study to PACS server.
func (c *Client) Store(req STOWRequest) (interface{}, error) {
	url := c.stowEndpoint + "/studies/"

	if req.StudyInstanceUID != "" {
		url += req.StudyInstanceUID
	}

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	writer.SetBoundary(c.boundary)
	header := textproto.MIMEHeader{}
	header.Set("Content-Type", "application/dicom")

	for _, p := range req.Parts {
		w, err := writer.CreatePart(header)
		if err != nil {
			return nil, err
		}
		if _, err = w.Write(p); err != nil {
			return nil, err
		}
	}

	if err := writer.Close(); err != nil {
		return nil, err
	}

	r, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}

	// The RFC 2045 doc states that certain values cannot be used as parameter values in the Content-Type header,
	// which includes '/', so the `application/dicom` needs to be wrapped by double quotes.
	r.Header.Set("Content-Type", fmt.Sprintf("multipart/related; type=\"application/dicom\"; boundary=%s", c.boundary))
	r.Header.Set("Accept", "application/dicom+json")
	if c.clientId != "" {
		err = c.getAccessToken()
		if err != nil {
			return nil, err
		}
	}
	if c.authorization != "" {
		r.Header.Set("Authorization", c.authorization)
	}
	if c.optionFuncs != nil {
		for _, fn := range *c.optionFuncs {
			if fn == nil {
				continue
			}
			if err := fn(r); err != nil {
				return nil, err
			}
		}
	}
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}

	if resp != nil && resp.StatusCode != 200 {
		return nil, errors.New("status = " + resp.Status)
	}

	var result STOWResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", err
	}

	// Convert the map to a JSON string
	//jsonResult, err := json.Marshal(result)
	//if err != nil {
	//	return "", err
	//}
	//fmt.Println(result)
	//if len(result.SuccessResponse.Value) < 1 {
	//	return "", errors.New("not load")
	//}
	//result.GetStudyies()

	return result, nil
}

type STOWResponse struct {
	ErrorResponse struct {
		Value []struct {
			ReferencedSOPClassUID struct {
				Value []string `json:"Value"`
				Vr    string   `json:"vr"`
			} `json:"00081150"`
			ReferencedSOPInstanceUID struct {
				Value []string `json:"Value"`
				Vr    string   `json:"vr"`
			} `json:"00081155"`
			FailureReason struct {
				Value []int  `json:"Value"`
				Vr    string `json:"vr"`
			} `json:"00081197"`
		} `json:"Value"`
		Vr string `json:"vr"`
	} `json:"00081198"`

	SuccessResponse struct {
		Value []struct {
			ReferencedSOPClassUID struct {
				Value []string `json:"Value"`
				Vr    string   `json:"vr"`
			} `json:"00081150"`
			ReferencedSOPInstanceUID struct {
				Value []string `json:"Value"`
				Vr    string   `json:"vr"`
			} `json:"00081155"`
			RetrieveURL struct {
				Value []string `json:"Value"`
				Vr    string   `json:"vr"`
			} `json:"00081190"`
			FailedAttributesSequence struct {
				Vr string `json:"vr"`
			} `json:"00741048"`
		} `json:"Value"`
		Vr string `json:"vr"`
	} `json:"00081199"`
}
