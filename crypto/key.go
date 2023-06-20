package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/big"

	lc "github.com/libp2p/go-libp2p-core/crypto"
)

func genPrivKey(secret []byte) (*PrivKey, error) {
	privKey := PrivKey{}
	copy(privKey[:], secret)
	return &privKey, nil
}

func GenPrivKey() (*PrivKey, error) {
	p256, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return genPrivKey(p256.D.Bytes())
}

func GenPrivKeyFromSeed(seed []byte) (*PrivKey, error) {
	seedHash := sha256.Sum256(seed)
	return genPrivKey(seedHash[:])
}

func GenPrivKeyFromBytes(privKeyBytes []byte) (*PrivKey, error) {
	privKey := PrivKey{}
	copy(privKey[:], privKeyBytes)
	err := privKey.Check()
	if err != nil {
		return nil, err
	}
	return &privKey, nil
}

func (privKey PrivKey) Check() error {
	if len(privKey) != PrivKeySize {
		return fmt.Errorf("improper privkey spec: size")
	}
	return nil
}

func (privKey PrivKey) Bytes() []byte {
	return privKey[:]
}

func (privKey PrivKey) Equals(target PrivKey) bool {
	return bytes.Equal(privKey.Bytes(), target.Bytes())
}

func (privKey PrivKey) String() string {
	return hex.EncodeToString(privKey[:])
}

func (privKey PrivKey) MarshalJSON() ([]byte, error) {
	data := make([]byte, PrivKeySize*2+2)
	data[0] = '"'
	data[len(data)-1] = '"'
	copy(data[1:], privKey.String())
	return data, nil
}

func (privKey *PrivKey) UnmarshalJSON(data []byte) error {
	if len(data) != PrivKeySize*2+2 {
		return fmt.Errorf("privKeyJSON size %d != expected %d",
			len(data), PrivKeySize*2+2,
		)
	}

	_, err := hex.Decode(privKey[:], data[1:len(data)-1])
	if err != nil {
		return err
	}

	return nil
}

func (privKey PrivKey) ToECDSA() *ecdsa.PrivateKey {
	X, Y := c.ScalarBaseMult(privKey[:])
	return &ecdsa.PrivateKey{
		D: new(big.Int).SetBytes(privKey[:]),
		PublicKey: ecdsa.PublicKey{
			Curve: c,
			X:     X,
			Y:     Y,
		},
	}
}

func (privKey PrivKey) ToECDSAP2P() (lc.PrivKey, error) {
	pk, _, err := lc.ECDSAKeyPairFromKey(privKey.ToECDSA())
	if err != nil {
		return nil, err
	}

	return pk, nil
}

/*
func (privKey PrivKey) FromECDSA(*ecdsa.PrivateKey) {
	copy(privKey[:], *ecdsa.PrivateKey.D.Bytes())
}
*/

// PubKey related functions

func (privKey PrivKey) PubKey() *PubKey {
	pubKey := PubKey{PubKeyPrefix}

	priv := privKey.ToECDSA()
	X := priv.X.Bytes()
	Y := priv.Y.Bytes()

	copy(pubKey[33-len(X):], X)
	copy(pubKey[65-len(Y):], Y)

	return &pubKey
}

func GenPubKeyFromBytes(pubKeyBytes []byte) (*PubKey, error) {
	pubKey := PubKey{}
	copy(pubKey[:], pubKeyBytes)
	err := pubKey.Check()
	if err != nil {
		return nil, err
	}
	return &pubKey, nil
}

func (pubKey *PubKey) Check() error {
	if len(pubKey) != PubKeySize {
		return fmt.Errorf("improper pubkey spec: size")
	}
	if pubKey[0] != PubKeyPrefix {
		return fmt.Errorf("improper pubkey spec: prefix")
	}
	return nil
}

func (pubKey *PubKey) Bytes() []byte {
	return pubKey[:]
}

func (pubKey *PubKey) ToECDSA() *ecdsa.PublicKey {
	return &ecdsa.PublicKey{
		Curve: c,
		X:     new(big.Int).SetBytes(pubKey[1:33]),
		Y:     new(big.Int).SetBytes(pubKey[33:]),
	}
}

func (pubKey PubKey) Equals(target PubKey) bool {
	return bytes.Equal(pubKey.Bytes(), target.Bytes())
}

func (pubKey PubKey) String() string {
	return hex.EncodeToString(pubKey[:])
}

func (pubKey *PubKey) MarshalJSON() ([]byte, error) {
	data := make([]byte, PubKeySize*2+2)
	data[0] = '"'
	data[len(data)-1] = '"'
	copy(data[1:], pubKey.String())
	return data, nil
}

func (pubKey *PubKey) UnmarshalJSON(data []byte) error {
	if len(data) != PubKeySize*2+2 {
		return fmt.Errorf("pubKeyJSON size %d != expected %d",
			len(data), PubKeySize*2+2,
		)
	}
	_, err := hex.Decode(pubKey[:], data[1:len(data)-1])
	if err != nil {
		return err
	}
	return nil
}

func (pubKey PubKey) X() *big.Int {
	return pubKey.ToECDSA().X
}

func (pubKey PubKey) Y() *big.Int {
	return pubKey.ToECDSA().Y
}
