package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddr(t *testing.T) {
	privKey, err := GenPrivKey()
	assert.Nil(t, err)

	pubKey := privKey.PubKey()
	addr := pubKey.Addr()

	ok := addr.IsDrivenFrom(pubKey)
	assert.True(t, ok)

	clonedPubKey, err := GenPubKeyFromBytes(pubKey.Bytes())
	assert.Nil(t, err)

	clonedAddr := clonedPubKey.Addr()

	ok = clonedAddr.Equals(addr)
	assert.False(t, ok)
}
