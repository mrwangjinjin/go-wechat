package core

import (
	"encoding/xml"
	"net/http"
)

type Message interface {
	NewTextMessage(w *http.ResponseWriter, text *Text) ([]byte, error)
}

type MessageHeader struct {
	XMLName      xml.Name `xml:"xml"`
	ToUserName   string   `xml:"ToUserName"`
	FromUserName string   `xml:"FromUserName"`
	CreateTime   int64    `xml:"CreateTime"`
	MsgType      string   `xml:"MsgType"`
}

type Text struct {
	MessageHeader
	Content string `xml:"Content"`
}
