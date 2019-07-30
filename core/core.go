package core

type IClient interface {
	GetToken() (map[string]interface{}, error)
	RefreshToken() (map[string]interface{}, error)
}

type ClientConfig struct {
	AppId     string
	AppSecret string
	Token     string
	AesKey    string
	BaseUrl   string
}
