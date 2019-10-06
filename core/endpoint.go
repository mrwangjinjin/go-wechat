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

func (self *Endpoint) ModifyDomain(componentToken string) string {
	return fmt.Sprintf("%s/wxa/modify_domain?access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) CommitCode(componentToken string) string {
	return fmt.Sprintf("%s/wxa/commit?access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) Release(componentToken string) string {
	return fmt.Sprintf("%s/wxa/release?access_token=%s", self.baseUrl, componentToken)
}

func (self *Endpoint) CustomService(componentToken string) string {
	return fmt.Sprintf("%s/cgi-bin/message/custom/send?access_token=%s", self.baseUrl, componentToken)
}
