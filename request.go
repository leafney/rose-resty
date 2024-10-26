/**
 * @Author:      leafney
 * @GitHub:      https://github.com/leafney
 * @Project:     rose-resty
 * @Date:        2024-10-26 18:19
 * @Description:
 */

package rresty

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/go-resty/resty/v2"
	"github.com/leafney/rose"
	"net/http"
	"strings"
	"time"
)

type (
	Client struct {
		client *resty.Client

		// 自定义参数
		url               string
		method            string
		referer           string
		timeOut           int
		cookies           []*http.Cookie
		formData          map[string]string
		queryParams       map[string]string
		pathParams        map[string]string
		headers           map[string]string
		query             string
		token             string // bearer xxxx
		authStr           string
		bodyData          interface{}
		saveCookie        bool // 是否下载Cookie
		contentAcceptJson bool
	}

	Request struct {
		req        *resty.Request
		url        string
		method     string
		saveCookie bool
	}

	Result struct {
		Code   int
		Body   []byte
		String string
		Cookie string
	}
)

func NewClient(debug bool, timeout int64) *Client {
	c := resty.New()
	if debug {
		c.SetDebug(debug)
	}

	if timeout > 0 {
		c.SetTimeout(time.Duration(timeout) * time.Second)
	}

	c.SetHeaders(map[string]string{
		"Accept":     "*/*",
		"User-Agent": rose.ReqUserAgentPC(),
	})

	return &Client{
		client:      c,
		formData:    make(map[string]string),
		pathParams:  make(map[string]string),
		queryParams: make(map[string]string),
		headers:     make(map[string]string),
		cookies:     make([]*http.Cookie, 0),
		method:      "get",
	}
}

func (c *Client) SetDebug(debug bool) *Client {
	c.client.SetDebug(debug)
	return c
}

func (c *Client) SetTimeout(sec int64) *Client {
	if sec > 0 {
		c.client.SetTimeout(time.Duration(sec) * time.Second)
	}
	return c
}

func (c *Client) SetVerify(skip bool) *Client {
	if skip {
		c.client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	}
	return c
}

func (c *Client) Method(method string) *Client {
	if !rose.StrIsEmpty(method) {
		c.method = method
	}
	return c
}

func (c *Client) Get(url string) *Client {
	c.method = "get"
	c.url = url
	return c
}

func (c *Client) Post(url string) *Client {
	c.method = "post"
	c.url = url
	return c
}

func (c *Client) Put(url string) *Client {
	c.method = "put"
	c.url = url
	return c
}

func (c *Client) Delete(url string) *Client {
	c.method = "delete"
	c.url = url
	return c
}

func (c *Client) SetBaseURL(url string) *Client {
	if !rose.StrIsEmpty(url) {
		c.client.SetBaseURL(url)
	}
	return c
}

func (c *Client) SetReferer(referer string) *Client {
	if !rose.StrIsEmpty(referer) {
		c.referer = referer
	}
	return c
}

func (c *Client) SetCookies(cookies string) *Client {
	if !rose.StrIsEmpty(cookies) {
		c.cookies = rose.CookieFromStr(cookies)
	}
	return c
}

func (c *Client) SetPathParams(params map[string]string) *Client {
	for k, v := range params {
		c.pathParams[k] = v
	}
	return c
}

func (c *Client) SetPathParam(param, value string) *Client {
	c.pathParams[param] = value
	return c
}

func (c *Client) SetQueryParams(params map[string]string) *Client {
	for k, v := range params {
		c.queryParams[k] = v
	}
	return c
}

func (c *Client) SetQueryParam(param, value string) *Client {
	c.queryParams[param] = value
	return c
}

func (c *Client) SetQueryString(query string) *Client {
	if !rose.StrIsEmpty(query) {
		c.query = query
	}
	return c
}

func (c *Client) SetFormData(data map[string]string) *Client {
	for k, v := range data {
		c.formData[k] = v
	}
	return c
}

func (c *Client) SetBody(body interface{}) *Client {
	c.bodyData = body
	return c
}

func (c *Client) SetHeaders(headers map[string]string) *Client {
	for k, v := range headers {
		c.headers[k] = v
	}
	return c
}

func (c *Client) SetHeader(header, value string) *Client {
	c.headers[header] = value
	return c
}

// SetAuthBearerToken Authorization = bearer xxxx
func (c *Client) SetAuthBearerToken(token string) *Client {
	c.token = token
	return c
}

// SetAuthorization Authorization = xxxx
func (c *Client) SetAuthorization(auth string) *Client {
	c.authStr = auth
	return c
}

func (c *Client) SetContentAcceptJSON() *Client {
	c.contentAcceptJson = true
	return c
}

func (c *Client) SetContentTypeJSON() *Client {
	c.client.SetHeader("Content-Type", "application/json")
	return c
}

func (c *Client) SetContentType(content string) *Client {
	if !rose.StrIsEmpty(content) {
		c.client.SetHeader("Content-Type", content)
	}
	return c
}

func (c *Client) SetAccept(str string) *Client {
	if !rose.StrIsEmpty(str) {
		c.client.SetHeader("Accept", str)
	}
	return c
}

func (c *Client) SetAcceptJSON() *Client {
	c.client.SetHeader("Accept", "application/json")
	return c
}

func (c *Client) Send() *Request {
	req := c.client.R()

	if !rose.StrIsEmpty(c.authStr) {
		req.SetHeader("Authorization", c.authStr)
	}

	if !rose.StrIsEmpty(c.referer) {
		req.SetHeader("Referer", c.referer)
	}

	if c.contentAcceptJson {
		req.SetHeaders(map[string]string{
			"Accept":       "application/json",
			"Content-Type": "application/json",
		})
	}

	// header部分，可以覆盖其他已设置过的header项
	if len(c.headers) > 0 {
		req.SetHeaders(c.headers)
	}

	if len(c.pathParams) > 0 {
		req.SetPathParams(c.pathParams)
	}

	if len(c.query) > 0 {
		req.SetQueryString(c.query)
	}

	if len(c.queryParams) > 0 {
		req.SetQueryParams(c.queryParams)
	}

	if len(c.formData) > 0 {
		req.SetFormData(c.formData)
	}

	if len(c.cookies) > 0 {
		req.SetCookies(c.cookies)
	}

	if !rose.StrIsEmpty(c.token) {
		req.SetAuthToken(c.token)
	}

	if c.bodyData != nil {
		req.SetBody(c.bodyData)
	}

	return &Request{
		req:        req,
		url:        c.url,
		method:     c.method,
		saveCookie: false,
	}
}

func (r *Request) GetCookie(save bool) *Request {
	r.saveCookie = save
	return r
}

func (r *Request) Request() (*Result, error) {
	var (
		resp *resty.Response
		err  error
	)

	switch strings.ToUpper(r.method) {
	case "GET":
		resp, err = r.req.Get(r.url)
	case "POST":
		resp, err = r.req.Post(r.url)
	case "PUT":
		resp, err = r.req.Put(r.url)
	case "DELETE":
		resp, err = r.req.Delete(r.url)
	case "HEAD":
		resp, err = r.req.Head(r.url)
	case "PATCH":
		resp, err = r.req.Patch(r.url)
	default:
		err = errors.New("method not supported")
	}

	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}

	cook := make([]*http.Cookie, 0)
	if r.saveCookie {
		cook = resp.Cookies()
	}

	return &Result{
		Code:   resp.StatusCode(),
		Body:   resp.Body(),
		String: resp.String(),
		Cookie: rose.CookieToStr(cook),
	}, nil
}

func (r *Request) Download(savePath string) error {
	resp, err := r.req.SetOutput(savePath).Get(r.url)
	if err != nil {
		return err
	}
	if resp.StatusCode() != http.StatusOK {
		return fmt.Errorf("status code [%v]", resp.Status())
	}
	return nil
}

// 新增便捷调用方法
func (c *Client) GetJSON(url string, result interface{}) error {
	resp, err := c.Get(url).Send().Request()
	if err != nil {
		return err
	}
	return json.Unmarshal(resp.Body, result)
}
