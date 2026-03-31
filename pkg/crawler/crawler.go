package crawler

import (
	"io"
	"net/url"
	"strings"

	"golang.org/x/net/html"
)

type Form struct {
	Action string
	Method string
	Inputs map[string]string
}

func ExtractLinks(httpBody io.Reader, baseStr string) []string {
	var links []string
	baseURL, err := url.Parse(baseStr)
	if err != nil {
		return links
	}

	z := html.NewTokenizer(httpBody)
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}

		if tt == html.StartTagToken || tt == html.SelfClosingTagToken {
			t := z.Token()
			var targetAttr string
			switch t.Data {
			case "a":
				targetAttr = "href"
			case "form":
				targetAttr = "action"
			case "script":
				targetAttr = "src"
			}

			if targetAttr == "" {
				continue
			}

			for _, a := range t.Attr {
				if a.Key == targetAttr {
					link := cleanURL(a.Val, baseURL)
					if link != "" {
						links = appendUnique(links, link)
					}
					break
				}
			}
		}
	}
	return links
}

func ExtractForms(httpBody io.Reader, baseStr string) []Form {
	var forms []Form
	baseURL, err := url.Parse(baseStr)
	if err != nil {
		return forms
	}

	doc, err := html.Parse(httpBody)
	if err != nil {
		return forms
	}

	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" {
			form := Form{Inputs: make(map[string]string)}
			for _, a := range n.Attr {
				if a.Key == "action" {
					form.Action = cleanURL(a.Val, baseURL)
				}
				if a.Key == "method" {
					form.Method = strings.ToUpper(a.Val)
				}
			}

			if form.Method == "" {
				form.Method = "GET"
			}
			if form.Action == "" {
				form.Action = baseStr
			}

			extractInputs(n, form.Inputs)
			forms = append(forms, form)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return forms
}

func extractInputs(n *html.Node, inputs map[string]string) {
	if n.Type == html.ElementNode && n.Data == "input" {
		var name, value string
		for _, a := range n.Attr {
			if a.Key == "name" {
				name = a.Val
			}
			if a.Key == "value" {
				value = a.Val
			}
		}
		if name != "" {
			inputs[name] = value
		}
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		extractInputs(c, inputs)
	}
}

func cleanURL(rawURL string, baseURL *url.URL) string {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" || strings.HasPrefix(rawURL, "javascript:") || strings.HasPrefix(rawURL, "mailto:") {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	resolved := baseURL.ResolveReference(parsed)
	resolved.Fragment = ""
	if resolved.Host != baseURL.Host {
		return ""
	}
	return resolved.String()
}

func appendUnique(slice []string, s string) []string {
	for _, v := range slice {
		if v == s {
			return slice
		}
	}
	return append(slice, s)
}
