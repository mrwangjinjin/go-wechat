package open

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/mrwangjinjin/go-wechat/core"
	"github.com/mrwangjinjin/go-wechat/pkg/util"
	"log"
	"net/http"
	"net/url"
	"time"
)

const (
	ComponentTicketCacheKeyPrefix   = "CACHE_TICKET@@"
	ComponentTokenCacheKeyPrefix    = "CACHE_COMPONENT@@"
	AuthorizerTokenCacheKeyPrefix   = "CACHE_AUTHORIZER_TOKEN@@"
	MpAuthorizerTokenCacheKeyPrefix = "CACHE_AUTHORIZER_TOKEN_MP@@"
)

type Client struct {
	Http      *core.HttpClient
	Endpoint  *core.Endpoint
	Cache     core.Cache
	AppId     string
	AppSecret string
	Token     string
	AesKey    string
}

// NewClient
func NewClient(clientConfig *core.ClientConfig, cache core.Cache) *Client {
	return &Client{
		Http:      core.NewHttpClient(),
		Cache:     cache,
		Endpoint:  core.NewEndpoint(clientConfig.BaseUrl),
		AppId:     clientConfig.AppId,
		AppSecret: clientConfig.AppSecret,
		Token:     clientConfig.Token,
		AesKey:    clientConfig.AesKey,
	}
}

// GetAuthUrl 获取授权页网址
func (self *Client) GetAuthUrl(redirectUri string, authType uint8) string {
	preAuthCode, err := self.ApiCreatePreAuthCode()
	if err != nil {
		return ""
	}
	return fmt.Sprintf("https://mp.weixin.qq.com/cgi-bin/componentloginpage?component_appid=%s&pre_auth_code=%s&redirect_uri=%s&auth_type=%d",
		url.QueryEscape(self.AppId),
		url.QueryEscape(preAuthCode),
		url.QueryEscape(redirectUri),
		authType)
}

// GetToken
func (self *Client) GetToken(authorizerAppId string) (map[string]interface{}, error) {
	resp, err := self.Cache.Get(AuthorizerTokenCacheKeyPrefix + authorizerAppId)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	return util.JsonUnmarshal(string(resp)), nil
}

// RefreshToken
func (self *Client) RefreshToken(authorizerAppId, refreshToken string) (map[string]interface{}, error) {
	dst, err := json.Marshal(map[string]interface{}{
		"component_appid":          self.AppId,
		"authorizer_appid":         authorizerAppId,
		"authorizer_refresh_token": refreshToken,
	})
	token, err := self.ApiComponentToken()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	status, body, err := self.Http.Post(self.Endpoint.ApiAuthorizerToken(token), "application/json", dst)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	authorizerRefreshToken := util.JsonUnmarshalBytes(body)
	_ = self.Cache.SetEx(AuthorizerTokenCacheKeyPrefix+authorizerAppId, map[string]interface{}{
		"authorizer_access_token":  authorizerRefreshToken["authorizer_access_token"],
		"authorizer_refresh_token": authorizerRefreshToken["authorizer_refresh_token"],
		"expires_in":               time.Now().Unix() + 6600,
	}, 6600)
	return authorizerRefreshToken, nil
}

// ApiCreatePreAuthCode 获取预授权码
func (self *Client) ApiCreatePreAuthCode() (string, error) {
	dst, err := json.Marshal(map[string]interface{}{
		"component_appid": self.AppId,
	})
	token, err := self.ApiComponentToken()
	if err != nil {
		log.Println(err)
		return "", err
	}
	status, body, err := self.Http.Post(self.Endpoint.PreAuthCodoUrl(token), "application/json", dst)
	if err != nil {
		log.Println(err)
		return "", err
	}
	if status != http.StatusOK {
		return "", errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)

	return resp["pre_auth_code"].(string), nil
}

// ApiQueryAuth 使用授权码换取公众号或小程序的接口调用凭据和授权信息
func (self *Client) ApiQueryAuth(code string) (map[string]interface{}, error) {
	authorizerToken, err := self.getRawApiQueryAuth(code)
	if err != nil {
		log.Println(err)
		return authorizerToken, err
	}
	return authorizerToken, nil
}

// ApiQueryAuth 使用授权码换取公众号或小程序的接口调用凭据和授权信息
func (self *Client) getRawApiQueryAuth(code string) (map[string]interface{}, error) {
	dst, err := json.Marshal(map[string]interface{}{
		"component_appid":    self.AppId,
		"authorization_code": code,
	})
	token, err := self.ApiComponentToken()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	status, body, err := self.Http.Post(self.Endpoint.ApiQueryAuth(token), "application/json", dst)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	authorizerToken := util.JsonUnmarshalBytes(body)
	authorzationInfo := authorizerToken["authorization_info"].(map[string]interface{})
	authorzationInfo["expires_in"] = time.Now().Unix() + 6600
	err = self.Cache.SetEx(AuthorizerTokenCacheKeyPrefix+authorzationInfo["authorizer_appid"].(string), authorzationInfo, 6600)
	if err != nil {
		return nil, err
	}
	return authorzationInfo, nil
}

// ApiAuthorizerInfo 获取授权方的帐号基本信息
func (self *Client) ApiAuthorizerInfo(authorizerAppId string) (map[string]interface{}, error) {
	dst, err := json.Marshal(map[string]interface{}{
		"component_appid":  self.AppId,
		"authorizer_appid": authorizerAppId,
	})
	token, err := self.ApiComponentToken()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	status, body, err := self.Http.Post(self.Endpoint.ApiAuthorizerInfo(token), "application/json", dst)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	authorizerToken := util.JsonUnmarshalBytes(body)
	authorizerInfo := authorizerToken["authorizer_info"].(map[string]interface{})
	return authorizerInfo, nil
}

// ApiComponentToken 获取第三方平台component_access_token
func (self *Client) ApiComponentToken() (string, error) {
	exist := self.Cache.Exists(ComponentTokenCacheKeyPrefix + self.AppId)
	if !exist {
		componentToken, err := self.getRawApiComponentToken()
		if err != nil {
			log.Println(err)
			return "", err
		}
		return componentToken["component_access_token"].(string), nil
	}
	resp, err := self.Cache.Get(ComponentTokenCacheKeyPrefix + self.AppId)
	if err != nil {
		log.Println(err)
		return "", err
	}
	componentToken := util.JsonUnmarshal(resp)
	if componentToken == nil {
		return "", err
	}
	if time.Now().Unix() > int64(componentToken["expires_in"].(float64)) {
		componentToken, err := self.getRawApiComponentToken()
		if err != nil {
			log.Println(err)
			return "", err
		}
		return componentToken["component_access_token"].(string), nil
	}
	return componentToken["component_access_token"].(string), nil
}

// getRawApiComponentToken 获取第三方平台component_access_token
func (self *Client) getRawApiComponentToken() (map[string]interface{}, error) {
	dst, err := json.Marshal(map[string]interface{}{
		"component_appid":         self.AppId,
		"component_appsecret":     self.AppSecret,
		"component_verify_ticket": self.getComponentTicket(),
	})
	status, body, err := self.Http.Post(self.Endpoint.ComponentAccessTokenUrl(), "application/json", dst)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		log.Print(err)
		return nil, err
	}
	componentToken := util.JsonUnmarshalBytes(body)
	componentToken["expires_in"] = time.Now().Unix() + 6600
	_ = self.Cache.SetEx(ComponentTokenCacheKeyPrefix+self.AppId, componentToken, 6600)
	return componentToken, nil
}

// getComponentTicket 获取component_verify_ticket
func (self *Client) getComponentTicket() (ticket string) {
	exist := self.Cache.Exists(ComponentTicketCacheKeyPrefix + self.AppId)
	if !exist {
		return ""
	}
	resp, _ := self.Cache.Get(ComponentTicketCacheKeyPrefix + self.AppId)
	log.Println(ticket)
	log.Println(resp)
	componentVerifyTicket := util.JsonUnmarshal(resp)
	if componentVerifyTicket == nil {
		return ""
	}
	return string(componentVerifyTicket["component_verify_ticket"].(string))
}

// FastRegisterWeapp 快速注册小程序
func (self *Client) FastRegisterWeapp(data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	token, err := self.ApiComponentToken()
	if err != nil {
		return err
	}
	status, body, err := self.Http.Post(self.Endpoint.FastRegisterWeapp(token), "application/json", dst)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("注册失败:" + resp["errmsg"].(string))
	}

	return nil
}

// FastRegisterWeappSearch 快速注册小程序结果查询
func (self *Client) FastRegisterWeappSearch(data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	token, err := self.ApiComponentToken()
	if err != nil {
		return err
	}
	status, body, err := self.Http.Post(self.Endpoint.FastRegisterWeappSearch(token), "application/json", dst)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("注册失败:" + resp["errmsg"].(string))
	}

	return nil
}

// BindTester 绑定体验者账号
func (self *Client) BindTester(authorizerAccessToken, wechatId string) error {
	dst, err := json.Marshal(map[string]interface{}{
		"wechatid": wechatId,
	})
	status, body, err := self.Http.Post(self.Endpoint.BindTester(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// UnbindTester 解除绑定体验者账号
func (self *Client) UnbindTester(authorizerAccessToken, wechatId string) error {
	dst, err := json.Marshal(map[string]interface{}{
		"wechatid": wechatId,
	})
	status, body, err := self.Http.Post(self.Endpoint.UnbindTester(authorizerAccessToken), "application/json", dst)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// ModifyDomain 修改小程序服务器域名
func (self *Client) ModifyDomain(authorizerAccessToken string, data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	status, body, err := self.Http.Post(self.Endpoint.ModifyDomain(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// CommitCode 上传小程序代码
func (self *Client) CommitCode(authorizerAccessToken string, data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	status, body, err := self.Http.Post(self.Endpoint.CommitCode(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// SubmitAudit 提交审核
func (self *Client) SubmitAudit(authorizerAccessToken string, data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	status, body, err := self.Http.Post(self.Endpoint.SubmitAudit(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// UndoCodeAudit 审核撤回
func (self *Client) UndoCodeAudit(authorizerAccessToken string, data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	status, body, err := self.Http.Post(self.Endpoint.SubmitAudit(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// Release 小程序发布
func (self *Client) Release(authorizerAccessToken string, data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	status, body, err := self.Http.Post(self.Endpoint.Release(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}

// GetWxaCode 小程序码
func (self *Client) GetWxaCode(authorizerAccessToken string, data map[string]interface{}) ([]byte, error) {
	dst, err := json.Marshal(data)
	status, body, err := self.Http.Post(self.Endpoint.GetWxaCode(authorizerAccessToken), "application/json", dst)
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return body, nil
}

// GetLastAuditStatus 获取小程序最后一次审核状态
func (self *Client) GetLastAuditStatus(authorizerAccessToken string) (map[string]interface{}, error) {
	status, body, err := self.Http.Get(self.Endpoint.GetLastAuditStatus(authorizerAccessToken))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return resp, nil
}

// GetTemplateList 获取小程序代码模板
func (self *Client) GetTemplateList() (map[string]interface{}, error) {
	token, err := self.ApiComponentToken()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	status, body, err := self.Http.Get(self.Endpoint.GetTemplateList(token))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return resp, nil
}

// GetPage 获取已上传的代码的页面列表
func (self *Client) GetPage(authorizerAccessToken string) (map[string]interface{}, error) {
	status, body, err := self.Http.Get(self.Endpoint.GetPage(authorizerAccessToken))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if int(resp["errcode"].(float64)) != 0 {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return resp, nil
}

// MpLogin 第三方授权小程序登录
func (self *Client) MpLogin(authorizerAppId, code string) (map[string]interface{}, error) {
	token, err := self.ApiComponentToken()
	if err != nil {
		log.Println(err)
		return nil, err
	}
	status, body, err := self.Http.Get(self.Endpoint.JsCode2Session(authorizerAppId, code, self.AppId, token))
	if err != nil {
		log.Println(err)
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return resp, nil
}

// GetQrCode 小程序体验码
func (self *Client) GetQrCode(authorizerAccessToken, path string) ([]byte, error) {
	status, body, err := self.Http.Get(self.Endpoint.GetQrCode(authorizerAccessToken, path))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return body, nil
}

// GetQrCode 小程序体验码
func (self *Client) GetQrCodeWithoutPath(authorizerAccessToken string) ([]byte, error) {
	status, body, err := self.Http.Get(self.Endpoint.GetQrCodeWithoutPath(authorizerAccessToken))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return body, nil
}

// GetWxaQrCode 生成带参数小程序码
func (self *Client) GetWxaQrCode(authorizerAccessToken, path string, width int) ([]byte, error) {
	dst, err := json.Marshal(map[string]interface{}{
		"path":  path,
		"width": width,
	})
	status, body, err := self.Http.Post(self.Endpoint.CreateWxaQrCode(authorizerAccessToken), "application/json", dst)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return body, nil
}

// MemberAuth 获取小程序所有已绑定的体验者列表
func (self *Client) MemberAuth(authorizerAccessToken string) (map[string]interface{}, error) {
	status, body, err := self.Http.Get(self.Endpoint.MemberAuth(authorizerAccessToken))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return resp, nil
}

// OAuth2Authorize 获取服务号授权网址
func (self *Client) OAuth2Authorize(authorizerApppId, redirectUrl string) string {
	return self.Endpoint.OAuth2Authorize(authorizerApppId, url.QueryEscape(redirectUrl), self.AppId)
}

// OAuth2AccessToken 获取服务号授权信息
func (self *Client) OAuth2AccessToken(authorizerApppId, code string) (map[string]interface{}, error) {
	token, err := self.ApiComponentToken()
	if err != nil {
		return nil, err
	}

	status, body, err := self.Http.Get(self.Endpoint.OAuth2AccessToken(authorizerApppId, code, self.AppId, token))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return nil, errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return resp, nil
}

// OAuth2RefreshToken
func (self *Client) OAuth2RefreshToken(authorizerAppId, refreshToken string) (map[string]interface{}, error) {
	token, err := self.ApiComponentToken()
	if err != nil {
		return nil, err
	}
	status, body, err := self.Http.Get(self.Endpoint.OAuth2RefreshToken(authorizerAppId, self.AppId, token, refreshToken))
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, errors.New("网络错误")
	}
	authorizerRefreshToken := util.JsonUnmarshalBytes(body)
	_ = self.Cache.SetEx(MpAuthorizerTokenCacheKeyPrefix+authorizerAppId, map[string]interface{}{
		"authorizer_mp_access_token":  authorizerRefreshToken["authorizer_access_token"],
		"authorizer_mp_refresh_token": authorizerRefreshToken["authorizer_refresh_token"],
		"expires_in":                  time.Now().Unix() + 6600,
	}, 6600)
	return authorizerRefreshToken, nil
}

// CustomService
func (self *Client) CustomService(authorizerAccessToken string, data map[string]interface{}) error {
	dst, err := json.Marshal(data)
	if err != nil {
		return err
	}
	status, body, err := self.Http.Post(self.Endpoint.CustomService(authorizerAccessToken), "", dst)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return errors.New("网络错误")
	}
	resp := util.JsonUnmarshalBytes(body)
	log.Println(resp)
	if _, ok := resp["errcode"]; ok {
		return errors.New("操作失败:" + resp["errmsg"].(string))
	}
	return nil
}
