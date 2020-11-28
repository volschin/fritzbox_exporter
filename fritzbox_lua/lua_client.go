// Package lua_client implementes client for fritzbox lua UI API
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

// SessionInfo XML from login_sid.lua
type SessionInfo struct {
	SID       string `xml:"SID"`
	Challenge string `xml:"Challenge"`
	BlockTime int    `xml:"BlockTime"`
	Rights    string `xml:"Rights"`
}

// LuaSession for storing connection data and SID
type LuaSession struct {
	BaseURL     string
	Username    string
	Password    string
	SID         string
	SessionInfo SessionInfo
}

// LuaPage identified by path and params
type LuaPage struct {
	Path   string
	Params string
}

// LuaMetricValueDefinition definition for a single metric
type LuaMetricValueDefinition struct {
	Path        string
	Key         string
	Labels      []string
	FixedLabels map[string]string
}

// LuaMetricValue single value retrieved from lua page
type LuaMetricValue struct {
	Name   string
	Value  string
	Labels map[string]string
}

// LabelRename regex to replace labels to get rid of translations
type LabelRename struct {
	Pattern regexp.Regexp
	Name    string
}

func (lua *LuaSession) doLogin(response string) error {
	urlParams := ""
	if response != "" {
		urlParams = fmt.Sprintf("?response=%s&user=%s", response, lua.Username)
	}

	resp, err := http.Get(fmt.Sprintf("%s/login_sid.lua%s", lua.BaseURL, urlParams))
	if err != nil {
		return fmt.Errorf("Error calling login_sid.lua: %s", err.Error())
	}

	defer resp.Body.Close()
	dec := xml.NewDecoder(resp.Body)

	err = dec.Decode(&lua.SessionInfo)
	if err != nil {
		return fmt.Errorf("Error decoding SessionInfo: %s", err.Error())
	}

	return nil
}

func (lmvDef *LuaMetricValueDefinition) createValue(name string, value string) LuaMetricValue {
	lmv := LuaMetricValue{
		Name:   name,
		Value:  value,
		Labels: make(map[string]string),
	}

	for l := range lmvDef.FixedLabels {
		lmv.Labels[l] = lmvDef.FixedLabels[l]
	}

	return lmv
}

// Login perform loing and get SID
func (lua *LuaSession) Login() error {

	err := lua.doLogin("")
	if err != nil {
		return err
	}

	challenge := lua.SessionInfo.Challenge
	if lua.SessionInfo.SID == "0000000000000000" && challenge != "" {
		// no SID, but challenge so calc response
		hash := utf16leMd5(fmt.Sprintf("%s-%s", challenge, lua.Password))
		response := fmt.Sprintf("%s-%x", challenge, hash)
		err := lua.doLogin(response)

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

// LoadData load a lua bage and return content
func (lua *LuaSession) LoadData(page LuaPage) ([]byte, error) {
	dataURL := fmt.Sprintf("%s/%s", lua.BaseURL, page.Path)

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

		resp, err = http.Post(dataURL, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte(params)))
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			callDone = true
		} else if resp.StatusCode == http.StatusForbidden && !callDone {
			// we assume SID is expired, so retry login
		} else {
			return nil, fmt.Errorf("data.lua failed: %s", resp.Status)
		}
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		return nil, err
	}

	return body, nil
}

// ParseJSON generic parser for unmarshalling into map
func ParseJSON(jsonData []byte) (map[string]interface{}, error) {
	var data map[string]interface{}

	// Unmarshal or Decode the JSON to the interface.
	json.Unmarshal(jsonData, &data)

	return data, nil
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

// GetMetrics get metrics from parsed lua page for definition and rename labels
func GetMetrics(labelRenames *[]LabelRename, data map[string]interface{}, metricDef LuaMetricValueDefinition) ([]LuaMetricValue, error) {

	var values []interface{}
	var err error
	if metricDef.Path != "" {
		pathItems := strings.Split(metricDef.Path, ".")
		values, err = _getValues(data, pathItems, "")
		if err != nil {
			return nil, err
		}
	} else {
		values = make([]interface{}, 1)
		values[0] = data
	}

	name := metricDef.Path
	if name != "" {
		name += "."
	}
	name += metricDef.Key

	metrics := make([]LuaMetricValue, 0)
	for _, valUntyped := range values {
		switch v := valUntyped.(type) {
		case map[string]interface{}:
			value, exists := v[metricDef.Key]
			if exists {
				lmv := metricDef.createValue(name, toString(value))

				for _, l := range metricDef.Labels {
					lv, exists := v[l]
					if exists {
						lmv.Labels[l] = getRenamedLabel(labelRenames, toString(lv))
					}
				}

				metrics = append(metrics, lmv)
			}
		case []interface{}:
			// since type is array there can't be any labels to differentiate values, so only one value supported !
			index, err := strconv.Atoi(metricDef.Key)
			if err != nil {
				return nil, fmt.Errorf("item '%s' is an array, but index '%s' is not a number", metricDef.Path, metricDef.Key)
			}

			if index < 0 {
				// this is an index from the end of the values
				index += len(v)
			}

			if index >= 0 && index < len(v) {
				lmv := metricDef.createValue(name, toString(v[index]))
				metrics = append(metrics, lmv)
			} else {
				return nil, fmt.Errorf("index %d is invalid for array '%s' with length %d", index, metricDef.Path, len(v))
			}
		default:
			return nil, fmt.Errorf("item '%s' is not a hash or array, can't get value %s", metricDef.Path, metricDef.Key)
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

// helper for retrieving values from parsed JSON
func _getValues(data interface{}, pathItems []string, parentPath string) ([]interface{}, error) {

	value := data
	curPath := parentPath

	for i, p := range pathItems {
		switch vv := value.(type) {
		case []interface{}:
			if p == "*" {

				values := make([]interface{}, 0, len(vv))
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
					return nil, fmt.Errorf("item '%s' is an array, but path item '%s' is neither '*' nor a number", curPath, p)
				}

				if index < 0 {
					// this is an index from the end of the values
					index += len(vv)
				}

				if index >= 0 && index < len(vv) {
					value = vv[index]
				} else {
					return nil, fmt.Errorf("index %d is invalid for array '%s' with length %d", index, curPath, len(vv))
				}
			}

		case map[string]interface{}:
			var exits bool
			value, exits = vv[p]
			if !exits {
				return nil, fmt.Errorf("key '%s' not existing in hash '%s'", p, curPath)
			}

		default:
			return nil, fmt.Errorf("item '%s' is neither a hash or array", curPath)
		}

		if curPath == "" {
			curPath = p
		} else {
			curPath += "." + p
		}
	}

	values := make([]interface{}, 1)
	values[0] = value
	return values, nil
}

func toString(value interface{}) string {
	// should we better check or simple convert everything ????
	return fmt.Sprintf("%v", value)
}
