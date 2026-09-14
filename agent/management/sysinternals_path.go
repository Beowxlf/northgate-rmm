package management

import (
	"errors"
	"regexp"
	"strings"
	"unicode"
)

var trustDeviceName = regexp.MustCompile(`(?i)^(CON|PRN|AUX|NUL|CONIN\$|CONOUT\$|COM[1-9¹²³]|LPT[1-9¹²³])$`)

func validateWindowsTrustPath(path string) error {
	invalid := errors.New("Select one absolute ordinary local Windows file")
	if len(path) < 4 || len(path) > 1024 || !((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) || path[1:3] != `:\` || strings.ContainsAny(path[2:], `:/*?"<>|`) || strings.ContainsFunc(path, unicode.IsControl) {
		return invalid
	}
	for _, part := range strings.Split(path[3:], `\`) {
		if part == "" || part == "." || part == ".." || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") || trustDeviceName.MatchString(strings.SplitN(part, ".", 2)[0]) {
			return invalid
		}
	}
	return nil
}
