package utils

import (
	"github.com/sethvargo/go-password/password"
	"log"
	"strings"
	"unicode"
)

func FixHeaderKey(key string) string {
	arr := strings.Split(key, "-")
	var newArr []string
	for _, v := range arr {
		var str string
		if unicode.IsLower(rune(v[0])) {
			str = strings.ToUpper(string(v[0])) + v[1:]
		} else {
			str = v
		}
		newArr = append(newArr, str)
	}
	return strings.Join(newArr, "-")
}

func InitServerSecret() string {
	res, err := password.Generate(64, 10, 10, false, false)
	if err != nil {
		log.Fatal(err)
	}
	return res
}
