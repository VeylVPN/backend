package winps

import "encoding/base64"

func encode(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}
