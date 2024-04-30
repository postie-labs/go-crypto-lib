package crypto

import (
	"bytes"
	"crypto/elliptic"
	"math/big"
)

func (privKey *PrivKey) DeriveSharedKey(pubKeys ...*PubKey) ([]byte, error) {
	p := c.Params()
	p = toPoint(p.ScalarBaseMult(privKey.PubKey().b[1:]))
	for _, pubKey := range pubKeys {
		p = toPoint(p.ScalarBaseMult(pubKey.b[1:]))
	}
	return bytes.Join([][]byte{p.Gx.Bytes(), p.Gy.Bytes()}, nil), nil
}

func toPoint(x, y *big.Int) *elliptic.CurveParams {
	return &elliptic.CurveParams{
		P:       c.Params().P,
		N:       c.Params().N,
		B:       c.Params().B,
		Gx:      x,
		Gy:      y,
		BitSize: c.Params().BitSize,
		Name:    "custom",
	}
}
