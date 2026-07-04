package sms

// Aliyun (Alibaba Cloud) SMS — SendSms action on dysmsapi.aliyuncs.com.
// Auth: HMAC-SHA1 signature over canonical-ordered query params, base64,
// percent-encoded. Stdlib-only — no SDK dependency.
//
// Configuration mapping:
//   AccessKey → AccessKey ID
//   Secret    → AccessKey Secret
//   SignName  → 短信签名 (must be pre-approved on Aliyun console)
//   Template  → 模板 CODE (also pre-approved, must contain a ${code} slot)
//   Region    → endpoint region (default cn-hangzhou)
//
// Template params are sent as JSON: `{"code":"123456"}`. The template's
// slot must be named `code` for the OTP flow.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/imkerbos/mxid/internal/domain/setting"
)

type aliyunSender struct{}

func (aliyunSender) SendCode(ctx context.Context, cfg setting.SMS, phone, code string) error {
	if cfg.AccessKey == "" || cfg.Secret == "" || cfg.SignName == "" || cfg.Template == "" {
		return fmt.Errorf("aliyun sms: access_key / secret / sign_name / template required")
	}

	params := url.Values{}
	// Action-specific
	params.Set("Action", "SendSms")
	params.Set("Version", "2017-05-25")
	params.Set("PhoneNumbers", phone)
	params.Set("SignName", cfg.SignName)
	params.Set("TemplateCode", cfg.Template)
	tplParams, _ := json.Marshal(map[string]string{"code": code})
	params.Set("TemplateParam", string(tplParams))
	// Public RPC-style params
	params.Set("Format", "JSON")
	params.Set("AccessKeyId", cfg.AccessKey)
	params.Set("SignatureMethod", "HMAC-SHA1")
	params.Set("SignatureVersion", "1.0")
	params.Set("SignatureNonce", uuid.New().String())
	params.Set("Timestamp", time.Now().UTC().Format("2006-01-02T15:04:05Z"))
	params.Set("RegionId", regionOrDefault(cfg.Region))

	// Build the canonical string-to-sign per Aliyun spec:
	//   GET&%2F&<sorted+encoded params>
	signature := aliyunSign(params, cfg.Secret)
	params.Set("Signature", signature)

	endpoint := fmt.Sprintf("https://dysmsapi.aliyuncs.com/?%s", params.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return err
	}
	resp, err := smsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("aliyun send: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	// Aliyun returns 200 with a JSON body that carries Code = "OK" on
	// success. Any other Code is a logical failure (Throttling, BlackList,
	// signature problems, etc).
	var parsed struct {
		Code      string `json:"Code"`
		Message   string `json:"Message"`
		RequestId string `json:"RequestId"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("aliyun: parse response status=%d body=%s: %w", resp.StatusCode, string(raw), err)
	}
	if parsed.Code != "OK" {
		return fmt.Errorf("aliyun sms failed: %s — %s (req_id=%s)", parsed.Code, parsed.Message, parsed.RequestId)
	}
	return nil
}

func regionOrDefault(r string) string {
	if r == "" {
		return "cn-hangzhou"
	}
	return r
}

// aliyunSign produces the HMAC-SHA1 base64 signature over the canonical
// query string. The canonical form sorts params alphabetically and uses
// the aliyun-style percent-encoding (RFC 3986 with extra escapes).
func aliyunSign(params url.Values, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(aliyunEncode(k))
		b.WriteByte('=')
		b.WriteString(aliyunEncode(params.Get(k)))
	}
	stringToSign := "GET&" + aliyunEncode("/") + "&" + aliyunEncode(b.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// aliyunEncode applies the percent-encoding Aliyun expects: url.QueryEscape
// plus + → %20 and *, ~ adjustments per their docs.
func aliyunEncode(s string) string {
	out := url.QueryEscape(s)
	out = strings.ReplaceAll(out, "+", "%20")
	out = strings.ReplaceAll(out, "*", "%2A")
	out = strings.ReplaceAll(out, "%7E", "~")
	return out
}
