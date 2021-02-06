package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/mayankagwl/go-social/oauth1"
	"github.com/mayankagwl/go-social/oauth2"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var tokenAuthMap = map[string]oauth2.AuthStyle{
	"client_secret_auto":  oauth2.AuthStyleAutoDetect,
	"client_secret_basic": oauth2.AuthStyleInPayload,
	"client_secret_post":  oauth2.AuthStyleInHeader,
	"request_method_get":  oauth2.AuthStyleInParams,
}

func Driver(d *SocialDriver) *Config {
	conf := Config{}
	conf.driver = d
	return &conf
}

func (c *Config) SetCredentials(clientId, clientSecret string) *Config {
	c.ClientID = clientId
	c.ClientSecret = clientSecret
	return c
}

func (c *Config) SetApplicationKey(applicationKey string) *Config {
	c.ApplicationKey = applicationKey
	return c
}

func (c *Config) SetAdditionalScope(scopes []string) *Config {
	if scopes != nil && len(scopes) > 0 {
		for _, sp := range scopes {
			if !inSlice(sp, c.driver.Scope) {
				c.driver.Scope = append(c.driver.Scope, sp)
			}
		}
	}
	return c
}

func (c *Config) SetRedirectUrl(xhost string) *Config {
	c.RedirectURI = fmt.Sprintf(`https://%s:443/socialauth/validate`, xhost)
	return c
}

func (c *Config) SetTokenAuthType(authType string) *Config {
	defaultAuthStyle := "client_secret_auto"
	if inSlice(authType, []string{"client_secret_auto", "client_secret_basic", "client_secret_post", "request_method_get"}) {
		c.driver.TokenAuthType = &authType
	}
	c.driver.TokenAuthType = &defaultAuthStyle
	return c
}

func (c *Config) SetState(state string) *Config {
	c.State = state
	return c
}

func (c *Config) GetAuthorizationUrl() string {
	var authRequest string
	if c.driver.OAuthVersion == "2.0" {
		conf, _ := c.prepareOAuth2Config()
		codeOptions := prepareCodeOptions(c.driver.AuthorizationExtra)
		authRequest = conf.AuthCodeURL(c.State, codeOptions...)

	} else if c.driver.OAuthVersion == "1.0" {
		conf, _ := c.prepareOAuth1Config()
		requestToken, _, err := conf.RequestToken()
		fmt.Println("err", err)

		authorizationURL, err := conf.AuthorizationURL(requestToken)
		authRequest = authorizationURL.String()
	}
	return authRequest
}

func (c *Config) GetToken(vars url.Values) (interface{}, error) {
	var token interface{}
	if c.driver.OAuthVersion == "2.0" {
		code := vars.Get("code")
		conf, _ := c.prepareOAuth2Config()
		codeOptions := prepareCodeOptions(c.driver.TokenExtraQueryString)
		oauth2Token, err := conf.Exchange(context.Background(), code, codeOptions...)
		if err != nil {
			return nil, err
		}
		token = oauth2Token
	} else {
		requestToken := vars.Get("oauth_token")
		verifier := vars.Get("oauth_verifier")
		conf, _ := c.prepareOAuth1Config()
		accessToken, accessSecret, err := conf.AccessToken(requestToken, "", verifier)
		fmt.Println("err", err)
		// handle error
		//token := oauth1.NewToken(accessToken, accessSecret)
		oauth1Token := struct {
			Token       string `json:"access_token"`
			TokenSecret string `json:"token_secret"`
		}{
			Token:       accessToken,
			TokenSecret: accessSecret,
		}
		token = oauth1Token
	}
	return token, nil
}

func (c *Config) getHttpClientNToken(tokenSource interface{}, header map[string]string) (*http.Client, string) {
	var client *http.Client
	var accessToken string
	ctx := context.Background()
	if c.driver.OAuthVersion == "2.0" {
		conf, _ := c.prepareOAuth2Config()
		var token = tokenSource.(*oauth2.Token)
		accessToken = token.AccessToken
		client = conf.Client(ctx, token, c.replacePlaceHolderInMap(header, accessToken))
	} else {
		conf, _ := c.prepareOAuth1Config()
		token := tokenSource.(*oauth1.Token)
		accessToken = token.Token
		client = conf.Client(ctx, token)
	}
	return client, accessToken
}

func (c *Config) GetUserInfo(tokenSource interface{}) (map[string]interface{}, error) {
	profile, err := c.getProfileInfo(tokenSource, c.driver.UserInfoEndpoint, c.driver.UserInfoQueryString, c.driver.UserInfoHeader)
	if err != nil {
		return nil, err
	}
	if c.driver.UserInfoExtraEndpoint != nil {
		profileExtra, err := c.getProfileInfo(tokenSource, *c.driver.UserInfoExtraEndpoint, c.driver.UserInfoExtraQueryString, c.driver.UserInfoExtraHeader)
		if err != nil {
			return nil, err
		}
		profile["userInfoExtra"] = profileExtra
	}

	user := &User{}
	user.AssignMap(c.driver.Mapping, profile)
	user.Raw = profile

	userByte, _ := json.Marshal(user)
	var response = make(map[string]interface{})
	json.Unmarshal(userByte, &response)
	return response, nil
}

func (c *Config) prepareUserInfoEndpoint(endpoint string, options map[string]string, accessToken string) string {
	u, _ := url.Parse(endpoint)
	q := u.Query()
	if options != nil && len(options) > 0 {
		for k, v := range options {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	endpoint = strings.ReplaceAll(u.String(), "#accesstoken#", accessToken)
	endpoint = strings.ReplaceAll(endpoint, "#applicationkey#", c.ApplicationKey)
	return endpoint
}

func (c *Config) getProfileInfo(token interface{}, endpoint string, queryString, headers map[string]string) (map[string]interface{}, error) {
	client, accessToken := c.getHttpClientNToken(token, headers)
	profileEndpoint := c.prepareUserInfoEndpoint(endpoint, queryString, accessToken)
	req, err := client.Get(profileEndpoint)
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()
	res, err := ioutil.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}
	profileData, err := jsonDecode(res)
	if err != nil {
		return nil, err
	}
	return profileData, nil
}

func (c *Config) GetTokenQueryString(oauthToken interface{}) string {
	tokenBytes, _ := json.Marshal(oauthToken)
	var t Token
	json.Unmarshal(tokenBytes, &t)
	tokenQS := TokenQueryString{
		OAuthToken:             t.AccessToken,
		TokenType:              t.TokenType,
		RefreshToken:           t.RefreshToken,
		ExpiresOn:              t.Expiry,
		IdToken:                t.IdToken,
		UID:                    nil,
		ConsumerKey:            &c.ClientID,
		ConsumerSecret:         &c.ClientSecret,
		ConsumerId:             &c.ApplicationKey,
		XOAuthYahooGuid:        nil,
		SessionHandle:          t.RefreshToken,
		SessionHandleExpiresOn: time.Time{},
		AuthenticationToken:    nil,
		TokenSecret:            t.TokenSecret,
	}
	tokenQSStr, _ := json.Marshal(tokenQS)
	return string(tokenQSStr)
}

func (c *Config) replacePlaceHolderInMap(mapping map[string]string, accessToken string) map[string]string {
	if mapping != nil && len(mapping) > 0 {
		for k, v := range mapping {
			if strings.Contains(v, "#accesstoken#") {
				mapping[k] = strings.Replace(v, "#accesstoken#", accessToken, -1)
			}
			if strings.Contains(v, "#applicationkey#") {
				mapping[k] = strings.Replace(v, "#applicationkey#", c.ApplicationKey, -1)
			}
		}
	}
	return mapping
}

func (c *Config) replacePlaceHolderInUrlValues(query url.Values, accessToken string) url.Values {
	if query != nil && len(query) > 0 {
		for k, _ := range query {
			v := query.Get(k)
			if strings.Contains(v, "#accesstoken#") {
				query.Set(k, strings.Replace(v, "#accesstoken#", accessToken, -1))
			}
			if strings.Contains(v, "#applicationkey#") {
				query.Set(k, strings.Replace(v, "#applicationkey#", c.ApplicationKey, -1))
			}
		}
	}
	return query
}

func (c *Config) prepareOAuth2Config() (*oauth2.Config, error) {
	conf := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		RedirectURL:  c.RedirectURI,
		Scopes:       c.driver.Scope,
		Endpoint: oauth2.Endpoint{
			AuthURL:  *c.driver.AuthorizationEndpoint,
			TokenURL: *c.driver.TokenEndpoint,
		},
	}
	if c.driver.TokenAuthType != nil {
		conf.Endpoint.AuthStyle = tokenAuthMap[*c.driver.TokenAuthType]
	}
	return conf, nil
}

func (c *Config) prepareOAuth1Config() (*oauth1.Config, error) {
	conf := &oauth1.Config{
		ConsumerKey:    c.ClientID,
		ConsumerSecret: c.ClientSecret,
		CallbackURL:    c.RedirectURI,
		Endpoint: oauth1.Endpoint{
			RequestTokenURL: *c.driver.RequestTokenEndpoint,
			AuthorizeURL:    *c.driver.AuthorizationEndpoint,
			AccessTokenURL:  *c.driver.TokenEndpoint,
		},
	}
	return conf, nil
}

func prepareCodeOptions(options map[string]string) []oauth2.AuthCodeOption {
	var codeOptions []oauth2.AuthCodeOption
	if options != nil && len(options) > 0 {
		for k, v := range options {
			codeOptions = append(codeOptions, oauth2.SetAuthURLParam(k, v))
		}
	}
	return codeOptions
}
