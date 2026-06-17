package security

import "math/rand/v2"

func GenerateUID() uint16 {
	return uint16(rand.Uint32())
}
