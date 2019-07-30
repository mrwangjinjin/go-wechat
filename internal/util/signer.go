package util

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"sort"
)

func Sign(token, timestamp, nonce string) (signature string) {
	strs := sort.StringSlice{token, timestamp, nonce}
	strs.Sort()

	buf := make([]byte, 0, len(token)+len(timestamp)+len(nonce))
	buf = append(buf, strs[0]...)
	buf = append(buf, strs[1]...)
	buf = append(buf, strs[2]...)

	hashsum := sha1.Sum(buf)
	return hex.EncodeToString(hashsum[:])
}

func MsgSign(token, timestamp, nonce, encryptedMsg string) (signature string) {
	strs := sort.StringSlice{token, timestamp, nonce, encryptedMsg}
	strs.Sort()

	h := sha1.New()

	bufw := bufio.NewWriterSize(h, 128)
	_, _ = bufw.WriteString(strs[0])
	_, _ = bufw.WriteString(strs[1])
	_, _ = bufw.WriteString(strs[2])
	_, _ = bufw.WriteString(strs[3])
	_ = bufw.Flush()

	hashsum := h.Sum(nil)
	return hex.EncodeToString(hashsum)
}
