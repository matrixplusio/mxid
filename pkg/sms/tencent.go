package sms

// Tencent Cloud SMS v3 — SendSms action on sms.tencentcloudapi.com.
// Auth: TC3-HMAC-SHA256 signature over canonical request + string-to-sign
// per Tencent's SDK spec. Stdlib-only.
//
// Configuration mapping:
//   AccessKey → SecretId
//   Secret    → SecretKey
//   SignName  → 短信签名 (must be pre-approved on Tencent SMS console)
//   Template  → 模板 ID
//   Region    → endpoint region (default ap-guangzhou)
//
// Template params are sent as a positional array — the OTP `code` is the
// single positional arg the templates we care about take.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/imkerbos/mxid/internal/domain/setting"
)

type tencentSender struct{}

func (tencentSender) SendCode(ctx context.Context, cfg setting.SMS, phone, code string) error {
	if cfg.AccessKey == "" || cfg.Secret == "" || cfg.SignName == "" || cfg.Template == "" {
		return fmt.Errorf("tencent sms: access_key / secret / sign_name / template required")
	}

	region := cfg.Region
	if region == "" {
		region = "ap-guangzhou"
	}
	// Tencent requires a SmsSdkAppId — we ferry it through cfg.AccessKey
	// alongside the SecretId because the settings schema has no dedicated
	// field. Format: "<SecretId>|<SmsSdkAppId>".
	parts := strings.SplitN(cfg.AccessKey, "|", 2)
	if len(parts) != 2 {
		return fmt.Errorf("tencent sms: access_key must be '<SecretId>|<SmsSdkAppId>'")
	}
	secretID, sdkAppID := parts[0], parts[1]

	payload := map[string]any{
		"SmsSdkAppId":      sdkAppID,
		"SignName":         cfg.SignName,
		"TemplateId":       cfg.Template,
		"TemplateParamSet": []string{code},
		"PhoneNumberSet":   []string{phone},
	}
	bodyBytes, _ := json.Marshal(payload)

	const (
		service = "sms"
		host    = "sms.tencentcloudapi.com"
		algo    = "TC3-HMAC-SHA256"
		action  = "SendSms"
		version = "2021-01-11"
	)

	now := time.Now().UTC()
	timestamp := fmt.Sprintf("%d", now.Unix())
	date := now.Format("2006-01-02")

	// Canonical request
	canonicalURI := "/"
	canonicalQueryString := ""
	canonicalHeaders := fmt.Sprintf("content-type:application/json; charset=utf-8\nhost:%s\nx-tc-action:%s\n",
		host, strings.ToLower(action))
	signedHeaders := "content-type;host;x-tc-action"
	hashedRequestPayload := sha256hex(bodyBytes)
	canonicalRequest := strings.Join([]string{
		"POST", canonicalURI, canonicalQueryString,
		canonicalHeaders, signedHeaders, hashedRequestPayload,
	}, "\n")

	// String to sign
	credentialScope := fmt.Sprintf("%s/%s/tc3_request", date, service)
	stringToSign := strings.Join([]string{
		algo, timestamp, credentialScope, sha256hex([]byte(canonicalRequest)),
	}, "\n")

	// Signing key
	secretDate := hmacSHA256([]byte("TC3"+cfg.Secret), date)
	secretService := hmacSHA256(secretDate, service)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))

	authorization := fmt.Sprintf("%s Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		algo, secretID, credentialScope, signedHeaders, signature)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+host, bytes.NewReader(bodyBytes))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", authorization)
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("Host", host)
	req.Header.Set("X-TC-Action", action)
	req.Header.Set("X-TC-Timestamp", timestamp)
	req.Header.Set("X-TC-Version", version)
	req.Header.Set("X-TC-Region", region)

	resp, err := smsHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("tencent send: %w", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	var parsed struct {
		Response struct {
			Error *struct {
				Code    string `json:"Code"`
				Message string `json:"Message"`
			} `json:"Error"`
			RequestId     string `json:"RequestId"`
			SendStatusSet []struct {
				Code        string `json:"Code"`
				Message     string `json:"Message"`
				PhoneNumber string `json:"PhoneNumber"`
			} `json:"SendStatusSet"`
		} `json:"Response"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return fmt.Errorf("tencent: parse response status=%d body=%s: %w", resp.StatusCode, string(raw), err)
	}
	if parsed.Response.Error != nil {
		return fmt.Errorf("tencent sms failed: %s — %s (req_id=%s)",
			parsed.Response.Error.Code, parsed.Response.Error.Message, parsed.Response.RequestId)
	}
	for _, s := range parsed.Response.SendStatusSet {
		if s.Code != "Ok" {
			return fmt.Errorf("tencent sms phone=%s code=%s msg=%s", s.PhoneNumber, s.Code, s.Message)
		}
	}
	return nil
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}
