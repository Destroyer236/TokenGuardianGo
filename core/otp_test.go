package core

import (
	"testing"
	"time"
)

// 测试密钥：即 ASCII "12345678901234567890" 的 Base32 编码（RFC 4226/6238 附录示例密钥）。
const testSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestGenerateHOTPRFC4226 覆盖 RFC 4226 附录 D 的全部 10 个测试向量（6 位截断）。
func TestGenerateHOTPRFC4226(t *testing.T) {
	vectors := map[uint64]string{
		0: "755224",
		1: "287082",
		2: "359152",
		3: "969429",
		4: "338314",
		5: "254676",
		6: "287922",
		7: "162583",
		8: "399871",
		9: "520489",
	}
	for counter, want := range vectors {
		got, err := GenerateHOTP(testSecret, counter)
		if err != nil {
			t.Fatalf("HOTP(counter=%d): 意外错误 %v", counter, err)
		}
		if got != want {
			t.Errorf("HOTP(counter=%d) = %s, 期望 %s", counter, got, want)
		}
	}
}

// TestGenerateTOTPRFC6238 覆盖 RFC 6238 附录 B 的 SHA1 向量：
// T=59s 时 8 位码为 94287082，取 6 位应为 287082。
func TestGenerateTOTPRFC6238(t *testing.T) {
	at := time.Unix(59, 0)
	got, err := GenerateTOTP(testSecret, DefaultInterval, at)
	if err != nil {
		t.Fatalf("TOTP(T=59): 意外错误 %v", err)
	}
	if got != "287082" {
		t.Errorf("TOTP(T=59) = %s, 期望 287082", got)
	}

	// RFC 6238：T=1111111109 → 8 位 07081804 → 6 位 081804
	at = time.Unix(1111111109, 0)
	got, _ = GenerateTOTP(testSecret, DefaultInterval, at)
	if got != "081804" {
		t.Errorf("TOTP(T=1111111109) = %s, 期望 081804", got)
	}
}

// TestBase32PaddingEquivalent 无填充与补全填充的密钥必须生成相同验证码
// （对应 Python 版 _correct_padding 修复）。
func TestBase32PaddingEquivalent(t *testing.T) {
	at := time.Unix(59, 0)
	withPad, _ := GenerateTOTP("MFRGG===", DefaultInterval, at)   // "abc"
	noPad, err := GenerateTOTP("MFRGG", DefaultInterval, at)        // 同一密钥，缺填充
	if err != nil {
		t.Fatalf("缺填充密钥应能解码: %v", err)
	}
	if withPad != noPad {
		t.Errorf("补全失败: 'MFRGG' => %s, 'MFRGG===' => %s", noPad, withPad)
	}

	// 大小写与首尾空格也应被归一化
	mixed, _ := GenerateTOTP("  mfrgg  ", DefaultInterval, at)
	if mixed != noPad {
		t.Errorf("大小写/空格归一化失败: %s != %s", mixed, noPad)
	}
}

// TestValidateSecret 非法密钥必须报错，合法密钥必须通过。
func TestValidateSecret(t *testing.T) {
	if err := ValidateSecret(testSecret); err != nil {
		t.Errorf("合法密钥不应报错: %v", err)
	}
	for _, bad := range []string{"", "not@base32!!", "ABCDEFG*"} {
		if err := ValidateSecret(bad); err == nil {
			t.Errorf("非法密钥 %q 应报错", bad)
		}
	}
}

// TestSecondsRemaining 剩余秒数应落在 1..30。
func TestSecondsRemaining(t *testing.T) {
	r := SecondsRemaining(DefaultInterval, time.Unix(59, 0))
	if r != 1 {
		t.Errorf("T=59 的剩余秒数 = %d, 期望 1", r)
	}
	r = SecondsRemaining(DefaultInterval, time.Unix(60, 0))
	if r != 30 {
		t.Errorf("T=60 的剩余秒数 = %d, 期望 30", r)
	}
}
