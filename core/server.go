package core

import (
	"encoding/xml"
	"io/ioutil"
	"log"
	"net/http"
)

const (
	ComponentTicketCacheKeyPrefix = "CACHE_TICKET@@"
)

const (
	EventComponentVerifyTicket    = "component_verify_ticket"
	EventAuthorized               = "authorized"
	EventUpdateAuthorized         = "updateauthorized"
	EventUnauthorized             = "unauthorized"
	EventNotifyThirdFasteregister = "notify_third_fasteregister"
)

const (
	AutoTestMpId = "wxd101a85aa106f53e"
)

type Server struct {
	Cache     Cache
	AppId     string
	AppSecret string
	Token     string
	AesKey    string
}

func NewServer(clientConfig *ClientConfig, cache Cache) *Server {
	return &Server{
		Cache:     cache,
		AppId:     clientConfig.AppId,
		AppSecret: clientConfig.AppSecret,
		Token:     clientConfig.Token,
		AesKey:    clientConfig.AesKey,
	}
}

// Serve 处理事件推送
func (self *Server) Serve(w http.ResponseWriter, r *http.Request) {
	encryptType := r.URL.Query().Get("encrypt_type")
	if encryptType == "" {
		return
	}
	switch encryptType {
	default:
		fallthrough
	case "aes":
		decoder := MessageDecoder{
			Signature:    r.URL.Query().Get("signature"),
			Timestamp:    r.URL.Query().Get("timestamp"),
			Nonce:        r.URL.Query().Get("nonce"),
			MsgSignature: r.URL.Query().Get("msg_signature"),
			EncryptMsg:   self.ReadXML(r),
		}
		// 验证签名
		if !decoder.VerifySignature(self.Token) {
			return
		}
		// 解密消息
		decryptMsg, err := decoder.DecodeComponentVerifyTicket(self.AppId, self.AesKey)
		if err != nil {
			return
		}

		// 处理推送事件
		switch decryptMsg.InfoType {
		case EventComponentVerifyTicket:
			_ = self.Cache.SetEx(ComponentTicketCacheKeyPrefix+self.AppId, map[string]interface{}{
				"component_verify_ticket": decryptMsg.ComponentVerifyTicket,
			}, 60*10)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
			break
		case EventAuthorized:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
			break
		case EventUpdateAuthorized:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
			break
		case EventUnauthorized:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
			break
		case EventNotifyThirdFasteregister:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
			break
		default:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("success"))
			break
		}
	case "raw":
		return
	}
	return
}

func (self *Server) ReadXML(r *http.Request) []byte {
	defer func() {
		_ = r.Body.Close()
	}()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return []byte{}
	}
	return body
}

func (self *Server) EventServe(w http.ResponseWriter, r *http.Request) {
	log.Println(r.URL.String())
	encryptType := r.URL.Query().Get("encrypt_type")
	if encryptType == "" {
		return
	}
	switch encryptType {
	default:
		fallthrough
	case "aes":
		decoder := MessageDecoder{
			Signature:    r.URL.Query().Get("signature"),
			Timestamp:    r.URL.Query().Get("timestamp"),
			Nonce:        r.URL.Query().Get("nonce"),
			MsgSignature: r.URL.Query().Get("msg_signature"),
			EncryptMsg:   self.ReadXML(r),
		}
		// 验证签名
		if !decoder.VerifySignature(self.Token) {
			return
		}
		// 解密消息
		decryptMsg, err := decoder.DecodeEventMessage(self.AppId, self.AesKey)
		if err != nil {
			return
		}

		// 处理推送事件
		switch decryptMsg.MsgType {
		default:
			fallthrough
		case "text":

		}
	case "raw":
		return
	}
}

func (self *Server) NewTextMessage(w http.ResponseWriter, text *Text) ([]byte, error) {
	buf, err := xml.Marshal(text)
	if err != nil {
		return nil, err
	}
	return buf, nil
}
