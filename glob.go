package netident

import (
	"path"
	"strings"
)

func globMatch(pattern, value string) (bool, error) {
	return path.Match(strings.ToLower(pattern), strings.ToLower(value))
}

func validateGlob(pattern string) error {
	_, err := path.Match(pattern, "test")
	return err
}
