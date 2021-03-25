package core

import (
	"encoding/xml"
	"github.com/conetse/WXBizMsgCrypt"
	"github.com/mrwangjinjin/go-wechat/internal/util"
	"time"
)

type CipherRequestHttpBody struct {
	XMLName            xml.Name `xml:"xml"`
	AppId              string   `xml:"AppId"`
	Base64EncryptedMsg []byte   `xml:"Encrypt"`
}

type CDATAText struct {
	Text string `xml:",innerxml"`
}

type CipherResponseHttpBody struct {
	XMLName      xml.Name `xml:"xml"`
	Encrypt      string   `xml:"Encrypt"`
	MsgSignature string   `xml:"MsgSignature"`
	TimeStamp    string   `xml:"TimeStamp"`
	Nonce        string   `xml:"Nonce"`
}

type EventHeaderMessage struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
}

type EventMessage struct {
	EventHeaderMessage
	MsgId   int64  `xml:"MsgId"`
	Event   string `xml:"Event"`
	Reason  string `xml:"Reason"`
	Content string `xml:"Content"`
}

type NotifyHeaderMessage struct {
	XMLName    xml.Name `xml:"xml"`
	AppId      string   `xml:"AppId"`
	CreateTime int64    `xml:"CreateTime"`
	MsgType    string   `xml:"MsgType"`
	InfoType   string   `xml:"InfoType"`
}

type InfoMessage struct {
	XMLName            xml.Name `xml:"info"`
	Name               int64    `xml:"name"`
	Code               string   `xml:"code"`
	CodeType           int      `xml:code_type`
	LegalPersonaWechat string   `xml:"legal_persona_wechat"`
	LegalPersonaName   string   `xml:"legal_persona_name"`
	ComponentPhone     string   `xml:"component_phone"`
}

type NotifyMessage struct {
	NotifyHeaderMessage
	ComponentVerifyTicket string `xml:"ComponentVerifyTicket"`
	AuthorizerAppid       string `xml:"AuthorizerAppid"`
	AuthorizationCode     string `xml:"AuthorizationCode"`
	PreAuthCode           string `xml:"PreAuthCode"`
	Appid                 string `xml:"appid"`
	AuthCode              string `xml:"auth_code"`
	Status                int    `xml:"status"`
	InfoMessage
}

type MessageDecoder struct {
	Signature    string
	Timestamp    string
	Nonce        string
	MsgSignature string
	Random       []byte
	EncryptMsg   []byte
}

type MessageEncoder struct {
	Signature string
	Timestamp string
	Nonce     string
	Random    []byte
	RawMsg    []byte
}

func (self *MessageDecoder) VerifySignature(token string) bool {
	if self.Signature == "" {
		return false
	}
	if self.Timestamp == "" {
		return false
	}
	if self.Nonce == "" {
		return false
	}
	if self.MsgSignature == "" {
		return false
	}

	var msg CipherRequestHttpBody
	err := xml.Unmarshal(self.EncryptMsg, &msg)
	if err != nil {
		return false
	}
	hashedSignature := util.Sign(token, self.Timestamp, self.Nonce)
	if !util.SecureCompareString(self.Signature, hashedSignature) {
		return false
	}

	hashedMsgSignature := util.MsgSign(token, self.Timestamp, self.Nonce, string(msg.Base64EncryptedMsg))
	if !util.SecureCompareString(self.MsgSignature, hashedMsgSignature) {
		return false
	}
	return true
}

func (self *MessageDecoder) DecodeComponentVerifyTicket(appId, aesKey string) (NotifyMessage, error) {
	var msg CipherRequestHttpBody
	err := xml.Unmarshal(self.EncryptMsg, &msg)
	if err != nil {
		return NotifyMessage{}, err
	}
	random, msgPlaintext, err := util.DecryptMsg(appId, aesKey, string(msg.Base64EncryptedMsg))
	if err != nil {
		return NotifyMessage{}, err
	}
	self.Random = random
	var ticketMsg NotifyMessage
	err = xml.Unmarshal(msgPlaintext, &ticketMsg)
	if err != nil {
		return NotifyMessage{}, err
	}
	return ticketMsg, nil
}

func (self *MessageDecoder) DecodeEventMessage(appId, aesKey string) (EventMessage, error) {
	var msg CipherRequestHttpBody
	err := xml.Unmarshal(self.EncryptMsg, &msg)
	if err != nil {
		return EventMessage{}, err
	}
	random, msgPlaintext, err := util.DecryptMsg(appId, aesKey, string(msg.Base64EncryptedMsg))
	if err != nil {
		return EventMessage{}, err
	}
	self.Random = random
	var eventMsg EventMessage
	err = xml.Unmarshal(msgPlaintext, &eventMsg)
	if err != nil {
		return EventMessage{}, err
	}
	return eventMsg, nil
}

func (self *MessageEncoder) EncodeMessage(appId, token, aesKey string) (string, error) {
	cry, err := WXBizMsgCrypt.NewWXBizMsgCrypt(token, aesKey, appId)
	if err != nil {
		return "", err
	}
	_, str := cry.EncryptMsg(string(self.RawMsg), self.Nonce, time.Now().Unix())
	return str, nil
}
