package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/net/html"
)

// auditFrontend consumes the template as HTML and the locale as JSON. It checks
// the rendered-text/attribute interface, excluding developer comments/scripts.
func auditFrontend(root string) error {
	templates, err := filepath.Glob(filepath.Join(root, "web", "templates", "*.html"))
	if err != nil {
		return err
	}
	for _, path := range templates {
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		doc, err := html.Parse(file)
		file.Close()
		if err != nil {
			return err
		}
		var walk func(*html.Node) error
		walk = func(n *html.Node) error {
			if n.Type == html.ElementNode && (n.Data == "script" || n.Data == "style") {
				return nil
			}
			if n.Type == html.TextNode {
				if err := english(filepath.Base(path)+" text", n.Data); err != nil {
					return err
				}
			}
			if n.Type == html.ElementNode {
				for _, a := range n.Attr {
					if err := english(filepath.Base(path)+" attribute "+a.Key, a.Val); err != nil {
						return err
					}
				}
			}
			for child := n.FirstChild; child != nil; child = child.NextSibling {
				if err := walk(child); err != nil {
					return err
				}
			}
			return nil
		}
		if err := walk(doc); err != nil {
			return err
		}
	}
	b, err := os.ReadFile(filepath.Join(root, "web", "static", "i18n", "en-US.json"))
	if err != nil {
		return err
	}
	var resources interface{}
	if err := json.Unmarshal(b, &resources); err != nil {
		return err
	}
	if err := english("English browser resources", resources); err != nil {
		return err
	}
	if len(templates) == 0 {
		return fmt.Errorf("no frontend templates found")
	}
	return nil
}
