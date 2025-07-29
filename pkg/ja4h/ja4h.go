// Copyright 2025 Adel "0x4D31" Ka
// Licensed under the Apache License, Version 2.0.
//
// This file incorporates the JA4H fingerprinting method, which is
// licensed under the FoxIO License 1.1 and includes certain usage
// restrictions: https://github.com/FoxIO-LLC/ja4/blob/main/LICENSE

package ja4h

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// FromRequest returns the JA4H fingerprint string for req.
// orderedHeaderNames should contain the request header names in
// the exact order they were received, lower-cased.
func FromRequest(req *http.Request, orderedHeaderNames []string) string {
	a := buildA(req, orderedHeaderNames)
	b := buildB(orderedHeaderNames)
	c, d := buildCD(req.Header["Cookie"])
	return fmt.Sprintf("%s_%s_%s_%s", a, b, c, d)
}

func buildA(req *http.Request, ordered []string) string {
	// positions 1-2: method
	method := strings.ToLower(req.Method)
	if len(method) >= 2 {
		method = method[:2]
	}

	// positions 3-4: HTTP version
	version := "11"
	switch req.Proto {
	case "HTTP/3.0", "HTTP/3":
		version = "30"
	case "HTTP/2.0", "HTTP/2":
		version = "20"
	case "HTTP/1.1":
		version = "11"
	case "HTTP/1.0":
		version = "10"
	case "HTTP/0.9":
		version = "09"
	}

	// position 5: cookie header present?
	c := 'n'
	if len(req.Header["Cookie"]) > 0 {
		c = 'c'
	}

	// position 6: referer header present?
	r := 'n'
	if len(req.Header["Referer"]) > 0 {
		r = 'r'
	}

	// positions 7-8: header count excluding cookie and referer
	count := 0
	for _, h := range ordered {
		if h == "cookie" || h == "referer" {
			continue
		}
		count++
	}
	if count > 99 {
		count = 99
	}
	hcount := fmt.Sprintf("%02d", count)

	// positions 9-12: primary accept-language
	al := req.Header.Get("Accept-Language")
	lang := "0000"
	if al != "" {
		token := strings.Split(al, ",")[0]
		token = strings.Split(token, ";")[0]
		token = strings.ToLower(token)
		token = strings.ReplaceAll(token, "-", "")
		token = strings.ReplaceAll(token, "_", "")
		if len(token) < 4 {
			token = (token + "0000")[:4]
		} else {
			token = token[:4]
		}
		lang = token
	}

	return fmt.Sprintf("%s%s%c%c%s%s", method, version, c, r, hcount, lang)
}

func buildB(ordered []string) string {
	list := make([]string, 0, len(ordered))
	for _, h := range ordered {
		if h == "cookie" || h == "referer" {
			continue
		}
		list = append(list, h)
	}
	s := strings.Join(list, ",")
	if s == "" {
		return strings.Repeat("0", 12)
	}
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum)[:12]
}

func buildCD(cookieHeaders []string) (string, string) {
	if len(cookieHeaders) == 0 {
		zeros := strings.Repeat("0", 12)
		return zeros, zeros
	}

	var names []string
	var namevals []string
	for _, line := range cookieHeaders {
		parts := strings.Split(line, ";")
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			kv := strings.SplitN(p, "=", 2)
			name := kv[0]
			value := ""
			if len(kv) == 2 {
				value = kv[1]
			}
			names = append(names, name)
			namevals = append(namevals, name+"="+value)
		}
	}

	sort.Strings(names)
	sort.Strings(namevals)

	joinedNames := strings.Join(names, ",")
	joinedNV := strings.Join(namevals, ",")
	hashNames := sha256.Sum256([]byte(joinedNames))
	hashNV := sha256.Sum256([]byte(joinedNV))
	return fmt.Sprintf("%x", hashNames)[:12], fmt.Sprintf("%x", hashNV)[:12]
}
