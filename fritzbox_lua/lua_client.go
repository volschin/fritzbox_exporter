// client for fritzbox lua API
package lua_client

// Copyright 2020 Andreas Krebs
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import (
	"bytes"
	"crypto/md5"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/text/encoding/unicode"
	"golang.org/x/text/transform"
)

// session XML from login_sid.lua
type SessionInfo struct {
	SID       string `xml:"SID"`
	Challenge string `xml:"Challenge"`
	BlockTime int    `xml:"BlockTime"`
	Rights    string `xml:"Rights"`
}

type LuaSession struct {
	BaseUrl     string
	Username    string
	Password    string
	SID         string
	SessionInfo SessionInfo
}

type LuaPage struct {
	Path   string
	Params string
}

type LuaMetricValueDefinition struct {
	Path   string
	Key    string
	Labels []string
}

type LuaMetricValue struct {
	Name   string
	Value  string
	Labels map[string]string
}

type LabelRename struct {
	Pattern regexp.Regexp
	Name    string
}

func (lua *LuaSession) do_Login(response string) error {
	url_params := ""
	if response != "" {
		url_params = fmt.Sprintf("?response=%s&user=%s", response, lua.Username)
	}

	resp, err := http.Get(fmt.Sprintf("%s/login_sid.lua%s", lua.BaseUrl, url_params))
	if err != nil {
		return errors.New(fmt.Sprintf("Error calling login_sid.lua: %s", err.Error()))
	}

	defer resp.Body.Close()
	dec := xml.NewDecoder(resp.Body)

	err = dec.Decode(&lua.SessionInfo)
	if err != nil {
		return errors.New(fmt.Sprintf("Error decoding SessionInfo: %s", err.Error()))
	}

	return nil
}

func (lua *LuaSession) Login() error {

	err := lua.do_Login("")
	if err != nil {
		return err
	}

	challenge := lua.SessionInfo.Challenge
	if lua.SessionInfo.SID == "0000000000000000" && challenge != "" {
		// no SID, but challenge so calc response
		hash := utf16leMd5(fmt.Sprintf("%s-%s", challenge, lua.Password))
		response := fmt.Sprintf("%s-%x", challenge, hash)
		err := lua.do_Login(response)

		if err != nil {
			return err
		}
	}

	sid := lua.SessionInfo.SID
	if sid == "0000000000000000" || sid == "" {
		return errors.New("LUA login failed - no SID received - check username and password")
	}

	lua.SID = sid

	return nil
}

func (lua *LuaSession) LoadData(page LuaPage) ([]byte, error) {
	data_url := fmt.Sprintf("%s/%s", lua.BaseUrl, page.Path)

	callDone := false
	var resp *http.Response
	var err error
	for !callDone {
		// perform login if no SID or previous call failed with (403)
		if lua.SID == "" || resp != nil {
			err = lua.Login()
			callDone = true // consider call done, since we tried login

			if err != nil {
				return nil, err
			}
		}

		// send by UI for data.lua: xhr=1&sid=xxxxxxx&lang=de&page=energy&xhrId=all&no_sidrenew=
		// but SID and page seem to be enough
		params := "sid=" + lua.SID
		if page.Params != "" {
			params += "&" + page.Params
		}

		resp, err = http.Post(data_url, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(params)))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			callDone = true
		} else if resp.StatusCode == http.StatusForbidden && !callDone {
			// we assume SID is expired, so retry login
		} else {
			return nil, errors.New(fmt.Sprintf("data.lua failed: %s", resp.Status))
		}
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return body, nil
}

func getRenamedLabel(labelRenames *[]LabelRename, label string) string {
	if labelRenames != nil {
		for _, lblRen := range *labelRenames {
			if lblRen.Pattern.MatchString(label) {
				return lblRen.Name
			}
		}
	}

	return label
}

func GetMetrics(labelRenames *[]LabelRename, data map[string]interface{}, metricDef LuaMetricValueDefinition) ([]LuaMetricValue, error) {

	var values []map[string]interface{}
	var err error
	if metricDef.Path != "" {
		pathItems := strings.Split(metricDef.Path, ".")
		values, err = _getValues(data, pathItems, "")
		if err != nil {
			return nil, err
		}
	} else {
		values = make([]map[string]interface{}, 1)
		values[0] = data
	}

	name := metricDef.Path
	if name != "" {
		name += "."
	}
	name += metricDef.Key

	metrics := make([]LuaMetricValue, 0)
	for _, valMap := range values {
		value, exists := valMap[metricDef.Key]
		if exists {
			lmv := LuaMetricValue{
				Name:   name,
				Value:  toString(value),
				Labels: make(map[string]string),
			}

			for _, l := range metricDef.Labels {
				lv, exists := valMap[l]
				if exists {
					lmv.Labels[l] = getRenamedLabel(labelRenames, toString(lv))
				}
			}

			metrics = append(metrics, lmv)
		}
	}

	return metrics, nil
}

// from https://stackoverflow.com/questions/33710672/golang-encode-string-utf16-little-endian-and-hash-with-md5
func utf16leMd5(s string) []byte {
	enc := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	hasher := md5.New()
	t := transform.NewWriter(hasher, enc)
	t.Write([]byte(s))
	return hasher.Sum(nil)
}

func ParseJSON(jsonData []byte) (map[string]interface{}, error) {
	var data map[string]interface{}

	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal(jsonData, &data)

	return data, nil
}

// helper for retrieving values from parsed JSON
func _getValues(data interface{}, pathItems []string, parentPath string) ([]map[string]interface{}, error) {

	value := data
	curPath := parentPath

	for i, p := range pathItems {
		switch vv := value.(type) {
		case []interface{}:
			if p == "*" {

				values := make([]map[string]interface{}, 0, len(vv))
				for index, u := range vv {
					subvals, err := _getValues(u, pathItems[i+1:], fmt.Sprintf("%s.%d", curPath, index))
					if err != nil {
						return nil, err
					}

					values = append(values, subvals...)
				}

				return values, nil
			} else {
				index, err := strconv.Atoi(p)
				if err != nil {
					return nil, errors.New(fmt.Sprintf("item '%s' is an array, but path item '%s' is neither '*' nor a number", curPath, p))
				}

				if index < 0 {
					// this is an index from the end of the values
					index += len(vv)
				}

				if index >= 0 && index < len(vv) {
					value = vv[index]
				} else {
					return nil, errors.New(fmt.Sprintf("index %d is invalid for array '%s' with length %d", index, curPath, len(vv)))
				}
			}

		case map[string]interface{}:
			var exits bool
			value, exits = vv[p]
			if !exits {
				return nil, errors.New(fmt.Sprintf("key '%s' not existing in hash '%s'", p, curPath))
			}

		default:
			return nil, errors.New(fmt.Sprintf("item '%s' is neither a hash or array", curPath))
		}

		if curPath == "" {
			curPath = p
		} else {
			curPath += "." + p
		}
	}

	vm, isType := value.(map[string]interface{})
	if !isType {
		return nil, errors.New(fmt.Sprintf("item '%s' is not a hash", curPath))
	}

	values := make([]map[string]interface{}, 1)
	values[0] = vm
	return values, nil
}

func toString(value interface{}) string {
	// should we better check or simple convert everything ????
	return fmt.Sprintf("%v", value)
}
