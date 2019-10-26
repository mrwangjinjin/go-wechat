package core

import "fmt"

type Endpoint struct {
	baseUrl string
}

func NewEndpoint(base string) *Endpoint {
	return &Endpoint{
		baseUrl: base,
	}
}

func (self *Endpoint) SetBaseUrl(base string) {
	self.baseUrl = base
}

func (self *Endpoint) ComponentAccessTokenUrl() string {
	return fmt.Sprintf("%s/cgi-bin/component/api_component_token", self.baseUrl)
}

func (self *Endpoint) PreAuthCodoUrl(componentToken string) string {
	return fmt.Sprintf("%s/cgi-bin/component/api_create_preauthcode?component_access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) ApiQueryAuth(componentToken string) string {
	return fmt.Sprintf("%s/cgi-bin/component/api_query_auth?component_access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) ApiAuthorizerToken(componentToken string) string {
	return fmt.Sprintf("%s/cgi-bin/component/api_authorizer_token?component_access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) ApiAuthorizerInfo(componentToken string) string {
	return fmt.Sprintf("%s/cgi-bin/component/api_get_authorizer_info?component_access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) FastRegisterWeapp(componentToken string) string {
	return fmt.Sprintf("%s/cgi-bin/component/fastregisterweapp?action=create&component_access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) BindTester(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/bind_tester?access_token=%s", self.baseUrl, authorizerAccessToken)
}
func (self *Endpoint) UnbindTester(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/unbind_tester?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) ModifyDomain(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/modify_domain?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) CommitCode(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/commit?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) SubmitAudit(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/submit_audit?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) UndoCodeAudit(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/undocodeaudit?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) Release(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/release?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) GetWxaCode(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/getwxacode?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) CustomService(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/cgi-bin/message/custom/send?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) GetLastAuditStatus(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/get_latest_auditstatus?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) JsCode2Session(authorizerAppId, code, componentAppId, componentToken string) string {
	return fmt.Sprintf("%s/sns/component/jscode2session?appid=%s&js_code=%s&grant_type=authorization_code&component_appid=%s&component_access_token=%s", self.baseUrl, authorizerAppId, code, componentAppId, componentToken)
}

func (self *Endpoint) GetTemplateList(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/gettemplatelist?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) GetQrCode(authorizerAccessToken, path string) string {
	return fmt.Sprintf("%s/wxa/get_qrcode?access_token=%s&path=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) GetQrCodeWithoutPath(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/get_qrcode?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) CreateWxaQrCode(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/cgi-bin/wxaapp/createwxaqrcode?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) MemberAuth(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/memberauth?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) GetPage(authorizerAccessToken string) string {
	return fmt.Sprintf("%s/wxa/get_page?access_token=%s", self.baseUrl, authorizerAccessToken)
}

func (self *Endpoint) OAuth2Authorize(authorizerAppId, redirectUrl, componentAppId string) string {
	return fmt.Sprintf("%s/connect/oauth2/authorize?appid=%s&redirect_uri=%s&response_type=code&scope=SCOPE&state=STATE&component_appid=%s#wechat_redirect", self.baseUrl, authorizerAppId, redirectUrl, componentAppId)
}

func (self *Endpoint) OAuth2AccessToken(authorizerAppId, code, componentAppId, componentAccessToken string) string {
	return fmt.Sprintf("%s/sns/oauth2/component/access_token?appid=%s&code=%s&grant_type=authorization_code&component_appid=%s&component_access_token=%s", self.baseUrl, authorizerAppId, code, componentAppId, componentAccessToken)
}

func (self *Endpoint) OAuth2RefreshToken(authorizerAppId, componentAppId, componentAccessToken, refreshToken string) string {
	return fmt.Sprintf("%s/sns/oauth2/component/refresh_token?appid=%s&grant_type=refresh_token&component_appid=%s&component_access_token=%s&refresh_token=%s", self.baseUrl, authorizerAppId, componentAppId, componentAccessToken, refreshToken)
}
