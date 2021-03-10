package engine

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/engine/cache"
	"crypto/engine/pkcs11"
	"crypto/sm2"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
)

var (
	oidNamedCurveP224    = asn1.ObjectIdentifier{1, 3, 132, 0, 33}
	oidNamedCurveP256    = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidNamedCurveP384    = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidNamedCurveP521    = asn1.ObjectIdentifier{1, 3, 132, 0, 35}
	oidNamedCurveP256SM2 = asn1.ObjectIdentifier{1, 2, 156, 10197, 1, 301}
)

func namedCurveFromOID(oid asn1.ObjectIdentifier) elliptic.Curve {
	switch {
	case oid.Equal(oidNamedCurveP224):
		return elliptic.P224()
	case oid.Equal(oidNamedCurveP256):
		return elliptic.P256()
	case oid.Equal(oidNamedCurveP384):
		return elliptic.P384()
	case oid.Equal(oidNamedCurveP521):
		return elliptic.P521()
	case oid.Equal(oidNamedCurveP256SM2):
		return sm2.P256Sm2()
	}
	return nil
}

//获取公钥64位有效字节
func getECPoint(p11lib *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (ecpt, oid []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, nil),
		pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, nil),
	}

	attr, err := p11lib.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, nil, fmt.Errorf("PKCS11: get(EC point) [%s]", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_EC_POINT {
			// workarounds, see above
			if (0 == (len(a.Value) % 2)) &&
				(byte(0x04) == a.Value[0]) &&
				(byte(0x04) == a.Value[len(a.Value)-1]) {
				ecpt = a.Value[0 : len(a.Value)-1] // Trim trailing 0x04
			} else if byte(0x04) == a.Value[0] && byte(0x04) == a.Value[2] {
				ecpt = a.Value[2:len(a.Value)]
			} else {
				ecpt = a.Value
			}
		} else if a.Type == pkcs11.CKA_EC_PARAMS {
			oid = a.Value
		}
	}
	if oid == nil || ecpt == nil {
		return nil, nil, fmt.Errorf("CKA_EC_POINT not found")
	}

	return ecpt, oid, nil
}

//取私钥32位有效字节
func getCKAValue(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, key pkcs11.ObjectHandle) (prv []byte, err error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	}

	attr, err := ctx.GetAttributeValue(session, key, template)
	if err != nil {
		return nil, fmt.Errorf("PKCS11: get prv [%s]", err)
	}

	for _, a := range attr {
		if a.Type == pkcs11.CKA_VALUE {
			prv = a.Value
		}
	}
	if prv == nil {
		return nil, fmt.Errorf("CKA_VALUE not found")
	}

	return prv, nil
}

//构建公钥
func buildPubKey(alg int, ecpt []byte) (pk crypto.PublicKey, err error) {
	switch alg {
	case ALG_ECDSA:
		pk, err = buildECPubKey(ecpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to build EC Public Key")
		}
	case ALG_SM2:
		pk, err = buildSM2PubKey(ecpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to build SM2 Public Key")
		}
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}

	return pk, nil
}

//构建私钥
func buildPriKey(alg int, prv32 []byte) (sk crypto.PrivateKey, err error) {
	switch alg {
	case ALG_ECDSA:
		sk = buildECPriKey(prv32)
	case ALG_SM2:
		sk = buildSM2PriKey(prv32)
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}

	return sk, nil
}

//根据64位有效字节构建完整SM2公钥
func buildSM2PubKey(ecpt []byte) (*sm2.PublicKey, error) {
	x, y := elliptic.Unmarshal(sm2.P256Sm2(), ecpt)
	if x == nil {
		return nil, fmt.Errorf("Failed Unmarshaling Public Key")
	}
	pk := &sm2.PublicKey{Curve: sm2.P256Sm2(), X: x, Y: y}

	return pk, nil
}

//根据64位有效字节构建完整EC公钥
func buildECPubKey(ecpt []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(elliptic.P256(), ecpt)
	if x == nil {
		return nil, fmt.Errorf("Failed Unmarshaling Public Key")
	}
	pk := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	return pk, nil
}

//根据32位有效字节构建完整SM2私钥
func buildSM2PriKey(prv32 []byte) *sm2.PrivateKey {
	d := new(big.Int).SetBytes(prv32)
	c := sm2.P256Sm2()
	priKey := new(sm2.PrivateKey)
	priKey.PublicKey.Curve = c
	priKey.D = d
	priKey.PublicKey.X, priKey.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

	return priKey
}

//根据32位有效字节构建完整EC私钥
func buildECPriKey(prv32 []byte) *ecdsa.PrivateKey {
	d := new(big.Int).SetBytes(prv32)
	c := elliptic.P256()
	priKey := new(ecdsa.PrivateKey)
	priKey.PublicKey.Curve = c
	priKey.D = d
	priKey.PublicKey.X, priKey.PublicKey.Y = c.ScalarBaseMult(d.Bytes())

	return priKey
}

//通过kid查询秘钥
func findKeyByKid(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, kid []byte, keyClass string) (*pkcs11.ObjectHandle, error) {
	var kclass uint
	switch keyClass {
	case PUBLIC_KEY:
		kclass = pkcs11.CKO_PUBLIC_KEY
	case PRIVATE_KEY:
		kclass = pkcs11.CKO_PRIVATE_KEY
	case SYM_KEY:
		kclass = pkcs11.CKO_SECRET_KEY
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, kclass),
		pkcs11.NewAttribute(pkcs11.CKA_ID, kid),
	}
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, err
	}

	// single session instance, assume one hit only
	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		return nil, err
	}
	if err = ctx.FindObjectsFinal(session); err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("Key not found [%s]", hex.Dump(kid))
	}

	return &objs[0], nil
}

func GetKeyHandle(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, kid []byte, keyClass string, c *cache.Cache) (key *pkcs11.ObjectHandle, err error) {
	cKey, found := c.Get(keyClass + string(kid))
	if found {
		key = cKey.(*pkcs11.ObjectHandle)
	} else {
		key, err = findKeyByKid(ctx, session, kid, keyClass)
		if err != nil {
			return nil, fmt.Errorf("FindKeyByKid failed [%s]", err)
		}
		c.Set(keyClass+string(kid), key, cache.NoExpiration)
	}
	return key, nil

}

func MarshalSignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(engSignature{r, s})
}

func UnmarshalSignature(sign []byte) (*big.Int, *big.Int, error) {
	var p11Sign engSignature

	_, err := asn1.Unmarshal(sign, &p11Sign)
	if err != nil {
		return nil, nil, err
	}
	return p11Sign.R, p11Sign.S, nil
}

//通过kid查询秘钥
func findKeyByLabel(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, label string, keyClass string) (*pkcs11.ObjectHandle, error) {
	var kclass uint
	switch keyClass {
	case PUBLIC_KEY:
		kclass = pkcs11.CKO_PUBLIC_KEY
	case PRIVATE_KEY:
		kclass = pkcs11.CKO_PRIVATE_KEY
	case SYM_KEY:
		kclass = pkcs11.CKO_SECRET_KEY
	}

	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, kclass),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}
	if err := ctx.FindObjectsInit(session, template); err != nil {
		return nil, err
	}

	// single session instance, assume one hit only
	objs, _, err := ctx.FindObjects(session, 1)
	if err != nil {
		return nil, err
	}
	if err = ctx.FindObjectsFinal(session); err != nil {
		return nil, err
	}

	if len(objs) == 0 {
		return nil, fmt.Errorf("Key not found [%s]", label)
	}

	return &objs[0], nil
}
