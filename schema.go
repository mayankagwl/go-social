package oauth

type Config struct {
	driver         *SocialDriver
	ClientID       string
	ClientSecret   string
	ApplicationKey string
	State          string
	RedirectURI    string
}

type SocialDriver struct {
	Name                     *string           `bson:"Name"`
	OAuthVersion             string            `bson:"OAuthVersion`
	Scope                    []string          `bson:"Scope"`
	AuthExtras               map[string]string `bson:"AuthExtras`
	RequestTokenEndpoint     *string           `bson:"RequestTokenEndpoint`
	AuthorizationEndpoint    *string           `bson:"AuthorizationEndpoint`
	AuthorizationExtra       map[string]string `bson:"AuthorizationExtra`
	TokenEndpoint            *string           `bson:"TokenEndpoint`
	TokenAuthType            *string           `bson:"TokenAuthType`
	TokenExtraQueryString    map[string]string `bson:"TokenExtraQueryString`
	UserInfoMethod           *string           `bson:"UserInfoMethod`
	UserInfoEndpoint         string            `bson:"UserInfoEndpoint`
	UserInfoQueryString      map[string]string `bson:"UserInfoQueryString`
	UserInfoHeader           map[string]string `bson:"UserInfoHeader`
	UserInfoPayload          map[string]string `bson:"UserInfoPayload`
	UserInfoExtraMethod      *string           `bson:"UserInfoExtraMethod`
	UserInfoExtraEndpoint    *string           `bson:"UserInfoExtraEndpoint`
	UserInfoExtraQueryString map[string]string `bson:"UserInfoExtraQueryString`
	UserInfoExtraHeader      map[string]string `bson:"UserInfoExtraHeader`
	UserInfoExtraPayload     map[string]string `bson:"UserInfoExtraPayload`
	Mapping                  map[string]string `bson:"Mapping`
}

/*type Token struct {
	AccessToken  string    `json:"access_token"`
	TokenType    *string   `json:"token_type"`
	RefreshToken *string   `json:"refresh_token"`
	Expiry       time.Time `json:"expiry"`
	IdToken      *string   `json:"id_token"`
	TokenSecret  *string   `json:"token_secret"`
}*/
