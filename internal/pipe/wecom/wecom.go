package wecom

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/caarlos0/env/v9"
	"github.com/caarlos0/log"
	"github.com/goreleaser/goreleaser/internal/tmpl"
	"github.com/goreleaser/goreleaser/pkg/context"
)

const (
	defaultMessageTemplate = `{ "message": "{{ .ProjectName }} {{ .Tag }} is out! Check it out at {{ .ReleaseURL }}"}`
	ContentTypeHeaderKey   = "Content-Type"
	UserAgentHeaderKey     = "User-Agent"
	UserAgentHeaderValue   = "gorleaser"
	AuthorizationHeaderKey = "Authorization"
	DefaultContentType     = "application/json; charset=utf-8"
	DefaultMsgType         = "text"
)

type TextMessage struct {
	MsgType string `json:"msgtype"`
	Text    struct {
		Content string `json:"content"`
	} `json:"text"`
}
type MarkdownMessage struct {
	MsgType  string `json:"msgtype"`
	Markdown struct {
		Content string `json:"content"`
	} `json:"markdown"`
}
type Pipe struct{}

func (Pipe) String() string                 { return "wecom" }
func (Pipe) Skip(ctx *context.Context) bool { return !ctx.Config.Announce.Wecom.Enabled }

type Config struct {
	BasicAuthHeader   string `env:"BASIC_AUTH_HEADER_VALUE"`
	BearerTokenHeader string `env:"BEARER_TOKEN_HEADER_VALUE"`
}

func (p Pipe) Default(ctx *context.Context) error {
	if ctx.Config.Announce.Wecom.MessageTemplate == "" {
		ctx.Config.Announce.Wecom.MessageTemplate = defaultMessageTemplate
	}
	if ctx.Config.Announce.Wecom.ContentType == "" {
		ctx.Config.Announce.Wecom.ContentType = DefaultContentType
	}
	if ctx.Config.Announce.Wecom.MsgType == "" {
		ctx.Config.Announce.Wecom.MsgType = DefaultMsgType
	}
	return nil
}

func (p Pipe) Announce(ctx *context.Context) error {
	var cfg Config
	if err := env.Parse(&cfg); err != nil {
		return fmt.Errorf("wecom: %w", err)
	}

	endpointURLConfig, err := tmpl.New(ctx).Apply(ctx.Config.Announce.Wecom.EndpointURL)
	if err != nil {
		return fmt.Errorf("wecom: %w", err)
	}
	if len(endpointURLConfig) == 0 {
		return errors.New("wecom: no endpoint url")
	}

	if _, err := url.ParseRequestURI(endpointURLConfig); err != nil {
		return fmt.Errorf("wecom: %w", err)
	}
	endpointURL, err := url.Parse(endpointURLConfig)
	if err != nil {
		return fmt.Errorf("wecom: %w", err)
	}

	msg, err := tmpl.New(ctx).Apply(ctx.Config.Announce.Wecom.MessageTemplate)
	if err != nil {
		return fmt.Errorf("wecom: %w", err)
	}

	log.Infof("posting: '%s'", msg)
	customTransport := http.DefaultTransport.(*http.Transport).Clone()

	customTransport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: ctx.Config.Announce.Wecom.SkipTLSVerify,
	}

	client := &http.Client{
		Transport: customTransport,
	}
	var msgStr string
	switch ctx.Config.Announce.Wecom.MsgType {
	case "text":
		var m TextMessage
		m.MsgType = "text"
		m.Text.Content = msg
		jsons, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("wecom: %w", err)
		}
		msgStr = string(jsons)
	case "markdown":
		var m MarkdownMessage
		m.MsgType = "markdown"
		m.Markdown.Content = msg
		jsons, err := json.Marshal(m)
		if err != nil {
			return fmt.Errorf("wecom: %w", err)
		}
		msgStr = string(jsons)
	default:
		fmt.Println("invalid msgtype")
	}

	req, err := http.NewRequest(http.MethodPost, endpointURL.String(), strings.NewReader(msgStr))
	if err != nil {
		return fmt.Errorf("wecom: %w", err)
	}
	req.Header.Add(ContentTypeHeaderKey, ctx.Config.Announce.Wecom.ContentType)
	req.Header.Add(UserAgentHeaderKey, UserAgentHeaderValue)

	if cfg.BasicAuthHeader != "" {
		log.Debugf("set basic auth header")
		req.Header.Add(AuthorizationHeaderKey, cfg.BasicAuthHeader)
	} else if cfg.BearerTokenHeader != "" {
		log.Debugf("set bearer token header")
		req.Header.Add(AuthorizationHeaderKey, cfg.BearerTokenHeader)
	}

	for key, value := range ctx.Config.Announce.Wecom.Headers {
		log.Debugf("Header Key %s / Value %s", key, value)
		req.Header.Add(key, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("wecom: %w", err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated, http.StatusAccepted, http.StatusNoContent:
		log.Infof("Post OK: '%v'", resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		log.Infof("Response : %v\n", string(body))
		return nil
	default:
		return fmt.Errorf("request failed with status %v", resp.Status)
	}
}
