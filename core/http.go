package core

import (
	"bytes"
	"io/ioutil"
	"net/http"
)

type HttpClient struct {
	http *http.Client
}

func NewHttpClient() *HttpClient {
	return &HttpClient{
		http: &http.Client{},
	}
}

func (self *HttpClient) Get(url string) (status int, body []byte, err error) {
	resp, err := self.http.Get(url)
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	return resp.StatusCode, body, nil
}

func (self *HttpClient) Post(url, contentType string, data []byte) (status int, body []byte, err error) {
	resp, err := self.http.Post(url, contentType, bytes.NewReader(data))
	if err != nil {
		return http.StatusInternalServerError, nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return http.StatusBadRequest, nil, err
	}
	return resp.StatusCode, body, nil
}

func (self *HttpClient) ReadXML(r *http.Request) []byte {
	defer func() {
		_ = r.Body.Close()
	}()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return []byte{}
	}
	return body
}
