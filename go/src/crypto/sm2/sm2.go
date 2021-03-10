/*
 refer to github.com/tjfoc/gmsm and the package of weizhang <d5c5ceb0@gmail.com>
*/

package sm2

// reference to ecdsa
import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"io"
	"math/big"

	"crypto/sm3"
	"fmt"
)

// combinedMult implements fast multiplication S1*g + S2*p (g - generator, p - arbitrary point)
type combinedMult interface {
	CombinedMult(bigX, bigY *big.Int, baseScalar, scalar []byte) (x, y *big.Int)
}

const (
	aesIV = "IV for <SM2> CTR"
)

// PublicKey represents an SM2 public key.
type PublicKey struct {
	elliptic.Curve
	X, Y *big.Int
}

// PrivateKey represents a SM2 private key.
type PrivateKey struct {
	PublicKey
	D *big.Int
}

type sm2Signature struct {
	R, S *big.Int
}

// The SM2's private key contains the public key
func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

// Sign signs msg with priv, reading randomness from rand. This method is
// intended to support keys where the private part is kept in, for example, a
// hardware module. Common uses should use the Sign function in this package
// directly.
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	pubkey := &PublicKey{
		Curve: priv.Curve,
		X:     priv.X,
		Y:     priv.Y,
	}
	hmsg := HashMsgZa(msg, pubkey)
	r, s, err := Sign(priv, hmsg)
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(sm2Signature{r, s})
}

func (pub *PublicKey) Verify(msg []byte, sign []byte) bool {
	//modified by heli
	sm2Sig := new(sm2Signature)
	if _, err := asn1.Unmarshal(sign, sm2Sig); err != nil {
		return false
	}
	if sm2Sig.R.Sign() <= 0 || sm2Sig.S.Sign() <= 0 {
		return false
	}

	hmsg := HashMsgZa(msg, pub)
	return Verify(pub, hmsg, sm2Sig.R, sm2Sig.S)
}

var one = new(big.Int).SetInt64(1)

// randFieldElement returns a random element of the field underlying the given
func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}

	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	n = n.Sub(n, one) //n-2

	// 1 <= k <= n-2
	k.Mod(k, n)
	k.Add(k, one)

	return
}

// GenerateKey generates a public and private key pair.
//func GenerateKey(c elliptic.Curve, rand io.Reader) (*PrivateKey, error) {
//	k, err := randFieldElement(c, rand)
//	if err != nil {
//		return nil, err
//	}
//
//	priv := new(PrivateKey)
//	priv.PublicKey.Curve = c
//	priv.D = k
//	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
//	return priv, nil
//}

func GenerateKey() (*PrivateKey, error) {
	c := P256Sm2()
	r := rand.Reader
	k, err := randFieldElement(c, r)
	if err != nil {
		return nil, err
	}

	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

var errZeroParam = errors.New("zero parameter")

// Sign signs a hash (which should be the result of hashing a larger message)
// using the private key, priv. If the hash is longer than the bit-length of the
// private key's curve order, the hash will be truncated to that length.  It
// returns the signature as a pair of integers. The security of the private key
// depends on the entropy of rand.
func Sign(priv *PrivateKey, hash []byte) (r, s *big.Int, err error) {
	// Get min(log2(q) / 2, 256) bits of entropy from rand.
	entropylen := (priv.Curve.Params().BitSize + 7) / 16
	if entropylen > 32 {
		entropylen = 32
	}
	entropy := make([]byte, entropylen)
	_, err = io.ReadFull(rand.Reader, entropy)
	if err != nil {
		return
	}

	// Initialize an SHA-512 hash context; digest ...
	md := sha512.New()
	md.Write(priv.D.Bytes()) // the private key,
	md.Write(entropy)        // the entropy,
	md.Write(hash)           // and the input hash;
	key := md.Sum(nil)[:32]  // and compute ChopMD-256(SHA-512),
	// which is an indifferentiable MAC.

	// Create an AES-CTR instance to use as a CSPRNG.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSPRNG that xors a stream of zeros with
	// the output of the AES-CTR instance.
	csprng := cipher.StreamReader{
		R: zeroReader,
		S: cipher.NewCTR(block, []byte(aesIV)),
	}

	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	e := new(big.Int).SetBytes(hash)
	for {
		for {
			k, err = randFieldElement(c, csprng)
			if err != nil {
				r = nil
				return
			}

			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				break
			}
			if t := new(big.Int).Add(r, k); t.Cmp(N) == 0 {
				break
			}
		}

		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}

	return
}

// Verify verifies the signature in r, s of hash using the public key, pub. Its
// return value records whether the signature is valid.
func Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if N.Sign() == 0 {
		return false
	}

	// Check if implements s*g + t*p
	var x *big.Int
	if opt, ok := c.(combinedMult); ok {
		x, _ = opt.CombinedMult(pub.X, pub.Y, s.Bytes(), t.Bytes())
	} else {
		x1, y1 := c.ScalarBaseMult(s.Bytes())
		x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
		x, _ = c.Add(x1, y1, x2, y2)
	}

	e := new(big.Int).SetBytes(hash)
	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r) == 0
}

func SignDigitToSignData(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(sm2Signature{r, s})
}

func SignDataToSignDigit(sign []byte) (*big.Int, *big.Int, error) {
	var sm2Sign sm2Signature

	_, err := asn1.Unmarshal(sign, &sm2Sign)
	if err != nil {
		return nil, nil, err
	}
	return sm2Sign.R, sm2Sign.S, nil
}

type zr struct {
	io.Reader
}

// Read replaces the contents of dst with zeros.
func (z *zr) Read(dst []byte) (n int, err error) {
	for i := range dst {
		dst[i] = 0
	}
	return len(dst), nil
}

var zeroReader = &zr{}

//Decrypt and Encrypt
func (priv *PrivateKey) Decrypt(data []byte) ([]byte, error) {
	return Decrypt(priv, data)
}

func (pub *PublicKey) Encrypt(data []byte) ([]byte, error) {
	return Encrypt(pub, data)
}

var (
	ErrKeyDataTooLong = fmt.Errorf("sm2: can't supply requested key data")
	ErrInvalidCurve   = fmt.Errorf("sm2: invalid elliptic curve")
	ErrInvalidMessage = fmt.Errorf("sm2: invalid message")
	ErrTIsZero        = fmt.Errorf("sm2: t is zero")
	ErrC3NoEqual      = fmt.Errorf("sm2: c3` is not equal to c3")
)

var (
	big2To32   = new(big.Int).Exp(big.NewInt(2), big.NewInt(32), nil)
	big2To32M1 = new(big.Int).Sub(big2To32, big.NewInt(1))
)

func incCounter(ctr []byte) {
	if ctr[3]++; ctr[3] != 0 {
		return
	} else if ctr[2]++; ctr[2] != 0 {
		return
	} else if ctr[1]++; ctr[1] != 0 {
		return
	} else if ctr[0]++; ctr[0] != 0 {
		return
	}
	return
}

func intToBytes(x int) []byte {
	var buf = make([]byte, 4)

	binary.BigEndian.PutUint32(buf, uint32(x))
	return buf
}

func kdf(x, y []byte, length int) ([]byte, bool) {
	var c []byte

	ct := 1
	h := sm3.New()
	x = append(x, y...)
	for i, j := 0, (length+31)/32; i < j; i++ {
		h.Reset()
		h.Write(x)
		h.Write(intToBytes(ct))
		hash := h.Sum(nil)
		if i+1 == j && length%32 != 0 {
			c = append(c, hash[:length%32]...)
		} else {
			c = append(c, hash...)
		}
		ct++
	}
	for i := 0; i < length; i++ {
		if c[i] != 0 {
			return c, true
		}
	}
	return c, false
}

func Encrypt(pub *PublicKey, msg []byte) (ct []byte, err error) {
	//kLen := (pub.Curve.Params().BitSize + 7) / 8

	for {
		k, err := randFieldElement(pub.Curve, rand.Reader)
		if err != nil {
			return nil, err
		}

		x1, y1 := p256.ScalarBaseMult(k.Bytes())
		x2, y2 := p256.ScalarMult(pub.X, pub.Y, k.Bytes())
		//x1, y1 := pub.Curve.ScalarBaseMult(k.Bytes())
		//x2, y2 := pub.Curve.ScalarMult(pub.X, pub.Y, k.Bytes())

		t, ok := kdf(x2.Bytes(), y2.Bytes(), len(msg))
		if !ok {
			return nil, errors.New("kdf failed")
		}

		bigT := new(big.Int).SetBytes(t)
		if eq := bigT.Cmp(big.NewInt(0)); eq == 0 {
			continue
		}

		bigT.Xor(bigT, new(big.Int).SetBytes(msg))
		c2 := make([]byte, len(msg))
		copy(c2[len(msg)-len(bigT.Bytes()):], bigT.Bytes())

		hash := sm3.New()
		hash.Write(x2.Bytes())
		hash.Write(msg)
		hash.Write(y2.Bytes())
		c3 := hash.Sum(nil)

		c1 := elliptic.Marshal(pub.Curve, x1, y1)
		ct = make([]byte, len(c1)+len(msg)+len(c3))
		copy(ct, c1)
		copy(ct[len(c1):], c2)
		copy(ct[len(c1)+len(c2):], c3)
		break
	}

	return
}
func Decrypt(prv *PrivateKey, c []byte) (m []byte, err error) {
	hash := sm3.New()
	hLen := hash.Size()

	kLen := (prv.PublicKey.Curve.Params().BitSize + 7) / 8

	R := new(PublicKey)
	R.Curve = prv.PublicKey.Curve
	R.X, R.Y = elliptic.Unmarshal(R.Curve, c[:kLen*2+1])

	x2, y2 := p256.ScalarMult(R.X, R.Y, prv.D.Bytes())
	//x2, y2 := prv.Curve.ScalarMult(R.X, R.Y, prv.D.Bytes())

	c1Len := kLen*2 + 1
	c2Len := len(c) - c1Len - hLen
	t, ok := kdf(x2.Bytes(), y2.Bytes(), c2Len)
	if !ok {
		return nil, errors.New("kdf failed")
	}

	bigT := new(big.Int).SetBytes(t)
	if eq := bigT.Cmp(big.NewInt(0)); eq == 0 {
		return nil, ErrTIsZero
	}

	c2Big := new(big.Int).SetBytes(c[c1Len : len(c)-hLen])

	bigT.Xor(bigT, c2Big)
	m1 := make([]byte, len(c)-(kLen*2+1)-hLen)
	copy(m1[len(c)-(kLen*2+1)-hLen-len(bigT.Bytes()):], bigT.Bytes())

	hash.Write(x2.Bytes())
	hash.Write(m1)
	hash.Write(y2.Bytes())
	c3 := hash.Sum(nil)

	c3t := c[len(c)-hLen:]
	if ok := bytes.Equal(c3, c3t); !ok {
		return nil, ErrC3NoEqual
	}

	return m1, nil
}

//added by yj
func (priv *PrivateKey) SignSm2(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	pubkey := &PublicKey{
		Curve: priv.Curve,
		X:     priv.X,
		Y:     priv.Y,
	}
	hmsg := HashMsgZa(msg, pubkey)
	r, s, err := Sign(priv, hmsg)
	if err != nil {
		return nil, err

	}

	return asn1.Marshal(sm2Signature{r, s})
}

//added by yj
func (pub *PublicKey) VerifySm2(msg []byte, sign []byte) bool {
	sm2Sig := new(sm2Signature)
	if _, err := asn1.Unmarshal(sign, sm2Sig); err != nil {
		return false
	}
	if sm2Sig.R.Sign() <= 0 || sm2Sig.S.Sign() <= 0 {
		return false
	}

	hmsg := HashMsgZa(msg, pub)
	return Verify(pub, hmsg, sm2Sig.R, sm2Sig.S)
}
