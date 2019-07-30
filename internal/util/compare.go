package util

import "crypto/subtle"

func SecureCompareString(given, actual string) bool {
	if subtle.ConstantTimeEq(int32(len(given)), int32(len(actual))) == 1 {
		if subtle.ConstantTimeCompare([]byte(given), []byte(actual)) == 1 {
			return true
		}
		return false
	}
	if subtle.ConstantTimeCompare([]byte(actual), []byte(actual)) == 1 {
		return false
	}
	return false
}
