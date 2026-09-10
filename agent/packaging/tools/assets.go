// Package tools contains the reviewed capture service installers.
package tools

import _ "embed"

//go:embed install-linux.sh
var Linux string

//go:embed northgate-wxlfgar.service
var Service string

//go:embed Install-Wxlfgar.ps1
var Windows string
