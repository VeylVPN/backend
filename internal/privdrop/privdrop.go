package privdrop

import "errors"

var ErrNotRoot = errors.New("must be run as root or Administrator")
