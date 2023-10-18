package crypto

import (
	"bytes"
	"crypto/elliptic"
	h "crypto/sha256"

	"github.com/btcsuite/btcutil/base58"
)

var preAddr = []byte{'t', 'c', 'k'}

// alias for backward compatibility
func (pubKey *PubKey) Address() *Addr {
	return pubKey.Addr()
}

func (pubKey *PubKey) Addr() *Addr {
	tmp := [AddrSize]byte{}
	pubKeyBytes := elliptic.Marshal(c, pubKey.X(), pubKey.Y())
	hash := h.Sum256(pubKeyBytes)
	b58 := base58.Encode(hash[:])
	copy(tmp[0:], preAddr)
	copy(tmp[len(preAddr):], b58)
	return &Addr{b: tmp}
}

func (addr *Addr) Bytes() []byte {
	return addr.b[:]
}

func (addr *Addr) String() string {
	return string(addr.Bytes())
}

func (addrA *Addr) IsDrivenFrom(pubKey *PubKey) bool {
	addrB := pubKey.Addr()
	return addrA.Equals(addrB)
}

func (addrA *Addr) Equals(addrB *Addr) bool {
	return bytes.Equal(addrA.b[:], addrA.b[:])
}
