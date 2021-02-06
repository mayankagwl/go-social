package oauth

import (
	"encoding/json"
	"github.com/tidwall/gjson"
	"reflect"
)

type User struct {
	ID        string
	Email     string
	FullName  string
	FirstName string
	LastName  string
	Avatar    string
	Raw       interface{}
}

func (u *User) setProperty(field string, value interface{}) {
	v := reflect.ValueOf(u).Elem().FieldByName(field)
	if v.IsValid() && v.CanSet() {
		val := reflect.ValueOf(value)
		if v.Type() == val.Type() {
			v.Set(val)
		}
	}
}

func (u *User) AssignMap(mapping map[string]string, data map[string]interface{}) {
	dataByte, _ := json.Marshal(data)
	dataStr := string(dataByte)
	for k := range mapping {
		value := gjson.Get(dataStr, k)
		u.setProperty(mapping[k], value.String())
	}
}
