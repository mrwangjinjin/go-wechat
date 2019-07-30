package util

import (
	"github.com/tidwall/gjson"
)

func JsonUnmarshal(json string) map[string]interface{} {
	m, ok := gjson.Parse(json).Value().(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}

func JsonUnmarshalBytes(json []byte) map[string]interface{} {
	m, ok := gjson.ParseBytes(json).Value().(map[string]interface{})
	if !ok {
		return nil
	}
	return m
}
