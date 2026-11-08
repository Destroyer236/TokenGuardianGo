// Package core 实现 Authenticator 的 2FA 引擎（TOTP/HOTP）与加密保险库。
//
// otp.go 是 Python 版 TokenGuardian (github.com/Hellohistory/TokenGuardian)
// token_guardian/core/otp.py 的忠实移植：HMAC-SHA1 + 动态截断（RFC 4226/6238），
// 6 位验证码，Base32 密钥自动补全 '=' 填充。
package core

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

const (
	// DefaultInterval 是 TOTP 的默认时间步长（与原版一致：30 秒）。
	DefaultInterval = 30 * time.Second
	// CodeDigits 是验证码位数（与原版一致：6 位）。
	CodeDigits = 6
)

// normalizeBase32 去掉空格与已有的 '='，转为大写后补齐正确的 '=' 填充。
// 对应 Python 版的 _correct_padding。
func normalizeBase32(secret string) string {
	s := strings.ToUpper(strings.TrimSpace(secret))
	s = strings.TrimRight(s, "=")
	pad := (8 - len(s)%8) % 8
	return s + strings.Repeat("=", pad)
}

// decodeSecret 将 Base32 密钥解码为原始字节，无效时返回错误。
func decodeSecret(secret string) ([]byte, error) {
	key, err := base32.StdEncoding.DecodeString(normalizeBase32(secret))
	if err != nil || len(key) == 0 {
		return nil, fmt.Errorf("无效的 Base32 密钥")
	}
	return key, nil
}

// dynamicTruncate 实现 RFC 4226 的动态截断，返回 digits 位整数。
func dynamicTruncate(mac []byte, digits int) int {
	offset := mac[len(mac)-1] & 0x0F
	code := binary.BigEndian.Uint32(mac[offset:offset+4]) & 0x7FFFFFFF
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	return int(code % mod)
}

// ValidateSecret 校验 Base32 密钥是否合法，非法时返回错误。
func ValidateSecret(secret string) error {
	_, err := decodeSecret(secret)
	return err
}

// GenerateHOTP 生成 HOTP 验证码（RFC 4226）。
// counter 为计数器值；返回 6 位验证码（左侧补零）。
func GenerateHOTP(secret string, counter uint64) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha1.New, key)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac.Write(buf[:])
	return fmt.Sprintf("%0*d", CodeDigits, dynamicTruncate(mac.Sum(nil), CodeDigits)), nil
}

// GenerateTOTP 生成 TOTP 验证码（RFC 6238，SHA1）。
// interval 为时间步长（<=0 时用默认 30 秒），at 为计算时刻；
// 返回 6 位验证码（左侧补零）。
func GenerateTOTP(secret string, interval time.Duration, at time.Time) (string, error) {
	if interval <= 0 {
		interval = DefaultInterval
	}
	counter := uint64(at.Unix() / int64(interval/time.Second))
	return GenerateHOTP(secret, counter)
}

// SecondsRemaining 返回 at 时刻所在 TOTP 窗口的剩余秒数（1..interval）。
func SecondsRemaining(interval time.Duration, at time.Time) int {
	if interval <= 0 {
		interval = DefaultInterval
	}
	secs := int(interval / time.Second)
	return secs - int(at.Unix()%int64(secs))
}
