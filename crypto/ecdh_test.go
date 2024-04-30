package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestECDHTwoParties(t *testing.T) {
	priv1, err := GenPrivKey()
	assert.Nil(t, err)

	priv2, err := GenPrivKey()
	assert.Nil(t, err)

	sharedKey1, err := priv1.DeriveSharedKey(priv2.PubKey())
	assert.Nil(t, err)

	sharedKey2, err := priv2.DeriveSharedKey(priv1.PubKey())
	assert.Nil(t, err)

	assert.Equal(t, sharedKey1, sharedKey2)
}

func TestECDHThreeParties(t *testing.T) {
	priv1, err := GenPrivKey()
	assert.Nil(t, err)

	priv2, err := GenPrivKey()
	assert.Nil(t, err)

	priv3, err := GenPrivKey()
	assert.Nil(t, err)

	sharedKey1, err := priv1.DeriveSharedKey(priv2.PubKey(), priv3.PubKey())
	assert.Nil(t, err)

	sharedKey2, err := priv2.DeriveSharedKey(priv1.PubKey(), priv3.PubKey())
	assert.Nil(t, err)

	sharedKey3, err := priv3.DeriveSharedKey(priv1.PubKey(), priv2.PubKey())
	assert.Nil(t, err)

	assert.Equal(t, sharedKey1, sharedKey2)
	assert.Equal(t, sharedKey2, sharedKey3)
}
