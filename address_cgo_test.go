//go:build cgo

package address

import (
	"testing"

	"github.com/filecoin-project/go-crypto"
	"github.com/stretchr/testify/assert"
)

func TestSecp256k1Address(t *testing.T) {
	assert := assert.New(t)

	sk, err := crypto.GenerateKey()
	assert.NoError(err)

	addr, err := NewSecp256k1Address(crypto.PublicKey(sk))
	assert.NoError(err)
	assert.Equal(SECP256K1, addr.Protocol())

	str, err := encode(Mainnet, addr)
	assert.NoError(err)

	maybe, err := decode(str)
	assert.NoError(err)
	assert.Equal(addr, maybe)

}
