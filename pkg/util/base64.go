package util

import "encoding/base64"

func Base64Encoding(v []byte) string {
	return base64.StdEncoding.EncodeToString(v)
}

func Base64Decoding(v []byte) (string, error) {
	actual, err := base64.StdEncoding.DecodeString(string(v))
	if err != nil {
		return "", err
	}
	return string(actual), nil
}
