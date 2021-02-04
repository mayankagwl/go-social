package main

import (
	"fmt"
	"github.com/mayankagwl/go-social/oauth1"
	"github.com/mayankagwl/go-social/oauth2"
)

func main() {
	conf1 := oauth2.Config{
		ClientID:     "",
		ClientSecret: "",
		Endpoint:     oauth2.Endpoint{},
		RedirectURL:  "",
		Scopes:       nil,
	}
	fmt.Printf("%#v", conf1)

	conf2 := oauth1.Config{
		ConsumerKey:    "",
		ConsumerSecret: "",
		CallbackURL:    "",
		Endpoint:       oauth1.Endpoint{},
		Realm:          "",
		Signer:         nil,
		Noncer:         nil,
	}
	fmt.Printf("%#v", conf2)
}
