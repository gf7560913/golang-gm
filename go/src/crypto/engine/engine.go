package engine

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/engine/cache"
	"crypto/engine/pkcs11"
	"crypto/sha256"
	"crypto/sm2"
	"crypto/sm3"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"time"
)

type Config struct {
	Lib   string
	Pin   string
	Label string
}

type Engine struct {
	Ctx      *pkcs11.Ctx
	Slot     uint
	Sessions chan pkcs11.SessionHandle
	Cache    *cache.Cache
}

type PublicKey struct {
	Kid []byte
	Alg int
}

type PrivateKey struct {
	Kid []byte
	PublicKey
}

type engSignature struct {
	R, S *big.Int
}

//初始化
func (e *Engine) Initialize(config *Config) error {
	if config == nil {
		return fmt.Errorf("p11 config can not be nil")
	}
	lib := config.Lib
	pin := config.Pin
	label := config.Label
	if lib == "" {
		return fmt.Errorf("No PKCS11 library default")
	}

	e.Ctx = pkcs11.New(lib)
	if e.Ctx == nil {
		return fmt.Errorf("Instantiate failed [%s]", lib)
	}

	e.Ctx.Initialize()
	slots, err := e.Ctx.GetSlotList(true)
	if err != nil {
		return fmt.Errorf("Could not get Slot List [%s]", err)
	}
	found := false
	for _, s := range slots {
		info, err := e.Ctx.GetTokenInfo(s)
		if err != nil {
			continue
		}
		if label == info.Label {
			found = true
			e.Slot = s
			break
		}
	}
	if !found {
		return fmt.Errorf("Could not find token with label [%s]", label)
	}

	session, err := e.Ctx.OpenSession(e.Slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return fmt.Errorf("OpenSession failed [%s]", err)
	}

	if pin == "" {
		return fmt.Errorf("No PIN set\n")
	}
	err = e.Ctx.Login(session, pkcs11.CKU_USER, pin)
	if err != nil {
		if err != pkcs11.Error(pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
			return fmt.Errorf("Login failed [%s]", err)
		}
	}
	e.Sessions = make(chan pkcs11.SessionHandle, 1000)
	e.ReturnSession(session)
	e.Cache = cache.New(24*time.Hour, 10*time.Minute)
	return nil
}

//获取session
func (e *Engine) GetSession() (session pkcs11.SessionHandle) {
	select {
	case session = <-e.Sessions:

	default:
		// cache is empty (or completely in use), create a new session
		s, err := e.Ctx.OpenSession(e.Slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
		if err != nil {
			panic(fmt.Errorf("OpenSession failed [%s]\n", err))
		}
		session = s
	}
	return session
}

//归还或关闭session
func (e *Engine) ReturnSession(session pkcs11.SessionHandle) {
	select {
	case e.Sessions <- session:
		// returned session back to session cache
	default:
		// have plenty of sessions in cache, dropping
		e.Ctx.CloseSession(session)
	}
}

//生成密钥对
func (e *Engine) KeyPairGen(alg int, label string, ephemeral bool) (pk *PublicKey, sk *PrivateKey, pkEntity crypto.PublicKey, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	pubkey_t := append(pubkey_base_t, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral))
	prvkey_t := append(prvkey_base_t, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral))
	var mechanism []*pkcs11.Mechanism

	switch alg {
	case ALG_ECDSA:
		oid, err := asn1.Marshal(oidNamedCurveP256)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Could not marshal oid [%s]", err.Error())
		}
		pubkey_t = append(pubkey_t, key_type_ec, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid))
		prvkey_t = append(prvkey_t, key_type_ec)
		mechanism = ckm_ec_key_pair_gen
	case ALG_SM2:
		oid, err := asn1.Marshal(oidNamedCurveP256SM2)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("Could not marshal oid [%s]", err.Error())
		}
		pubkey_t = append(pubkey_t, key_type_sm2, pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid))
		prvkey_t = append(prvkey_t, key_type_sm2)
		mechanism = ckm_sm2_key_pair_gen
	default:
		return nil, nil, nil, fmt.Errorf("Unsupported alg")
	}

	pub, prv, err := e.Ctx.GenerateKeyPair(session, mechanism, pubkey_t, prvkey_t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("P11: keypair generate failed [%s]", err)
	}

	ecpt, _, err := getECPoint(e.Ctx, session, pub)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Get EC Point failed [%s]", err)
	}

	var hash [32]byte
	var kid []byte
	switch alg {
	case ALG_ECDSA:
		hash = sha256.Sum256(ecpt)
	case ALG_SM2:
		hash = sm3.Sm3Sum(ecpt)
	default:
		return nil, nil, nil, fmt.Errorf("Unsupported alg")
	}
	kid = hash[:]

	setkid_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, kid),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, label),
	}

	err = e.Ctx.SetAttributeValue(session, pub, setkid_t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("P11: set-ID-to-KID[public] failed [%s]", err)
	}

	err = e.Ctx.SetAttributeValue(session, prv, setkid_t)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("P11: set-ID-to-KID[private] failed [%s]", err)
	}

	pk = &PublicKey{kid, alg}
	sk = &PrivateKey{kid, PublicKey{kid, alg}}

	pkEntity, err = buildPubKey(alg, ecpt)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Build PubKey failed [%s]", err)
	}

	e.Cache.Set(PUBLIC_KEY+string(kid), &pub, cache.NoExpiration)
	e.Cache.Set(PRIVATE_KEY+string(kid), &prv, cache.NoExpiration)

	return pk, sk, pkEntity, nil
}

//获取公钥
func (e *Engine) GetPublicKey(kid []byte) (pk interface{}, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	if kid == nil {
		return nil, fmt.Errorf("kid should not be nil")
	}

	pub, err := GetKeyHandle(e.Ctx, session, kid, PUBLIC_KEY, e.Cache)
	if err != nil {
		return nil, fmt.Errorf("findKeyByKid failed [%s]", err)
	}

	ecpt, oid, err := getECPoint(e.Ctx, session, *pub)
	if err != nil {
		return nil, fmt.Errorf("Get EC Point failed [%s]", err)
	}

	curveOid := new(asn1.ObjectIdentifier)
	_, err = asn1.Unmarshal(oid, curveOid)
	if err != nil {
		return nil, fmt.Errorf("Failed to Unmarshal oid [%s]", err)
	}
	curve := namedCurveFromOID(*curveOid)
	switch curve {
	case elliptic.P256():
		pk, err = buildECPubKey(ecpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to build Public Key [%s]", err)
		}
	case sm2.P256Sm2():
		pk, err = buildSM2PubKey(ecpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to build Public Key [%s]", err)
		}
	}

	return pk, nil
}

//获取私钥
func (e *Engine) GetPrivateKey(kid []byte) (sk []byte, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	if kid == nil {
		return nil, fmt.Errorf("kid should not be nil")
	}
	prv, err := GetKeyHandle(e.Ctx, session, kid, PRIVATE_KEY, e.Cache)
	if err != nil {
		return nil, fmt.Errorf("findKeyByKid failed [%s]", err)
	}

	sk, err = getCKAValue(e.Ctx, session, *prv)
	if err != nil {
		return nil, fmt.Errorf("P11: get CKA_VALUE failed [%s]", err)
	}

	return sk, nil
}

//获取公钥
func (e *Engine) GetPublicKeyByLabel(label string) (pk interface{}, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	pub, err := findKeyByLabel(e.Ctx, session, label, PUBLIC_KEY)
	if err != nil {
		return nil, fmt.Errorf("findKeyByKid failed [%s]", err)
	}

	ecpt, oid, err := getECPoint(e.Ctx, session, *pub)
	if err != nil {
		return nil, fmt.Errorf("Get EC Point failed [%s]", err)
	}

	curveOid := new(asn1.ObjectIdentifier)
	_, err = asn1.Unmarshal(oid, curveOid)
	if err != nil {
		return nil, fmt.Errorf("Failed to Unmarshal oid [%s]", err)
	}
	curve := namedCurveFromOID(*curveOid)
	switch curve {
	case elliptic.P256():
		pk, err = buildECPubKey(ecpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to build Public Key [%s]", err)
		}
	case sm2.P256Sm2():
		pk, err = buildSM2PubKey(ecpt)
		if err != nil {
			return nil, fmt.Errorf("Failed to build Public Key [%s]", err)
		}
	}

	return pk, nil
}

//获取私钥
func (e *Engine) GetPrivateKeyByLabel(label string) (sk []byte, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	prv, err := findKeyByLabel(e.Ctx, session, label, PRIVATE_KEY)
	if err != nil {
		return nil, fmt.Errorf("findKeyByKid failed [%s]", err)
	}

	sk, err = getCKAValue(e.Ctx, session, *prv)
	if err != nil {
		return nil, fmt.Errorf("P11: get CKA_VALUE failed [%s]", err)
	}

	return sk, nil
}

//导入公钥
func (e *Engine) PublicKeyImport(raw interface{}, alg int, label string, ephemeral bool) (pk *PublicKey, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	pubkey_t := append(pubkey_base_t, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))

	var ecpt, oid, kid []byte
	switch key := raw.(type) {
	case *ecdsa.PublicKey:
		ecpt = elliptic.Marshal(key.Curve, key.X, key.Y)
	case *sm2.PublicKey:
		ecpt = elliptic.Marshal(key.Curve, key.X, key.Y)
	default:
		return nil, fmt.Errorf("raw is not a public key")
	}

	var hash [32]byte
	switch alg {
	case ALG_ECDSA:
		hash = sha256.Sum256(ecpt)
		oid, err = asn1.Marshal(oidNamedCurveP256)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal oid [%s]", err.Error())
		}
		pubkey_t = append(pubkey_t, key_type_ec)
	case ALG_SM2:
		hash = sm3.Sm3Sum(ecpt)
		oid, err = asn1.Marshal(oidNamedCurveP256SM2)
		if err != nil {
			return nil, fmt.Errorf("Could not marshal oid [%s]", err.Error())
		}
		pubkey_t = append(pubkey_t, key_type_sm2)
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}

	ecpt = append([]byte{0x04, byte(len(ecpt))}, ecpt...)

	kid = hash[:]
	pubkey_t = append(pubkey_t, pkcs11.NewAttribute(pkcs11.CKA_EC_POINT, ecpt), pkcs11.NewAttribute(pkcs11.CKA_EC_PARAMS, oid), pkcs11.NewAttribute(pkcs11.CKA_ID, kid))

	pub, err := e.Ctx.CreateObject(session, pubkey_t)
	if err != nil {
		return nil, fmt.Errorf("P11: pubkey import failed [%s]", err)
	}

	pk = &PublicKey{kid, alg}

	e.Cache.Set(PUBLIC_KEY+string(kid), &pub, cache.NoExpiration)

	return pk, nil
}

//导入私钥
func (e *Engine) PrivateKeyImport(raw interface{}, alg int, label string, ephemeral bool) (sk *PrivateKey, err error) {
	session := e.GetSession()
	defer e.ReturnSession(session)

	prvkey_t := append(prvkey_base_t, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, !ephemeral), pkcs11.NewAttribute(pkcs11.CKA_LABEL, label))

	var ecpt, priKey, kid []byte
	switch key := raw.(type) {
	case *ecdsa.PrivateKey:
		ecpt = elliptic.Marshal(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y)
		priKey = key.D.Bytes()
	case *sm2.PrivateKey:
		ecpt = elliptic.Marshal(key.PublicKey.Curve, key.PublicKey.X, key.PublicKey.Y)
		priKey = key.D.Bytes()
	default:
		return nil, fmt.Errorf("raw is not a private key")
	}

	var hash [32]byte

	switch alg {
	case ALG_ECDSA:
		hash = sha256.Sum256(ecpt)
		prvkey_t = append(prvkey_t, key_type_ec, pkcs11.NewAttribute(pkcs11.CKA_VALUE, priKey))
	case ALG_SM2:
		hash = sm3.Sm3Sum(ecpt)
		prvkey_t = append(prvkey_t, key_type_sm2, pkcs11.NewAttribute(pkcs11.CKA_VALUE, priKey))
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}

	kid = hash[:]
	prvkey_t = append(prvkey_t, pkcs11.NewAttribute(pkcs11.CKA_ID, kid))

	prv, err := e.Ctx.CreateObject(session, prvkey_t)
	if err != nil {
		return nil, fmt.Errorf("P11: pubkey import failed [%s]", err)
	}

	sk = &PrivateKey{kid, PublicKey{kid, alg}}

	e.Cache.Set(PRIVATE_KEY+string(kid), &prv, cache.NoExpiration)

	return sk, nil
}

//删除私钥
func (e *Engine) DeleteKey(kid []byte, keyClass string) error {
	session := e.GetSession()
	defer e.ReturnSession(session)

	if kid == nil {
		return fmt.Errorf("kid should not be nil")
	}
	key, err := GetKeyHandle(e.Ctx, session, kid, keyClass, e.Cache)
	if err != nil {
		return fmt.Errorf("GetKeyHandle failed [%s]", err)
	}

	err = e.Ctx.DestroyObject(session, *key)
	if err != nil {
		return fmt.Errorf("Delete private key failed [%s]\n", err)
	}

	return nil
}

func (e *Engine) DeleteKeyByLabel(label string, keyClass string) error {
	session := e.GetSession()
	defer e.ReturnSession(session)

	key, err := findKeyByLabel(e.Ctx, session, label, keyClass)
	if err != nil {
		return fmt.Errorf("GetKeyHandle failed [%s]", err)
	}

	err = e.Ctx.DestroyObject(session, *key)
	if err != nil {
		return fmt.Errorf("Delete private key failed [%s]\n", err)
	}

	return nil
}

func (priv *PrivateKey) Public() crypto.PublicKey {
	return &priv.PublicKey
}

//签名
func (priv *PrivateKey) Sign(rand io.Reader, msg []byte, e *Engine) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("Engine can not be nil")
	}
	session := e.GetSession()
	defer e.ReturnSession(session)

	r, s, err := Sign(e.Ctx, session, msg, priv, e.Cache)
	if err != nil {
		return nil, err
	}
	return MarshalSignature(r, s)
}

//验签
func (key *PublicKey) Verify(msg []byte, sign []byte, e *Engine) (bool, error) {
	if e == nil {
		return false, fmt.Errorf("Engine can not be nil")
	}
	session := e.GetSession()
	defer e.ReturnSession(session)

	r, s, err := UnmarshalSignature(sign)
	if err != nil {
		return false, err
	}

	return Verify(e.Ctx, session, msg, r, s, key, e.Cache)
}

//加密
func (key *PublicKey) Encrypt(data []byte, e *Engine) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("Engine can not be nil")
	}
	session := e.GetSession()
	defer e.ReturnSession(session)

	return Encrypt(e.Ctx, session, data, key, e.Cache)
}

//解密
func (key *PrivateKey) Decrypt(data []byte, e *Engine) ([]byte, error) {
	if e == nil {
		return nil, fmt.Errorf("Engine can not be nil")
	}
	session := e.GetSession()
	defer e.ReturnSession(session)

	return Decrypt(e.Ctx, session, data, key, e.Cache)
}

//签名
func Sign(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, msg []byte, key *PrivateKey, c *cache.Cache) (r, s *big.Int, err error) {
	privateKey, err := GetKeyHandle(ctx, session, key.Kid, PRIVATE_KEY, c)
	if err != nil {
		return nil, nil, fmt.Errorf("Private key not found [%s]", err)
	}

	var mechanism []*pkcs11.Mechanism
	switch key.PublicKey.Alg {
	case ALG_ECDSA:
		mechanism = ckm_ec
	case ALG_SM2:
		mechanism = ckm_sm2_sign_verify
	}

	err = ctx.SignInit(session, mechanism, *privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("Sign-initialize  failed [%s]", err)
	}

	var sig []byte

	sig, err = ctx.Sign(session, msg)
	if err != nil {
		return nil, nil, fmt.Errorf("P11: sign failed [%s]", err)
	}

	switch key.PublicKey.Alg {
	case ALG_ECDSA:
		r := new(big.Int)
		s := new(big.Int)
		r.SetBytes(sig[0 : len(sig)/2])
		s.SetBytes(sig[len(sig)/2:])
		return r, s, nil
	case ALG_SM2:
		return UnmarshalSignature(sig)
	default:
		return nil, nil, fmt.Errorf("Unsupported alg")
	}
}

//验签
func Verify(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, msg []byte, r, s *big.Int, key *PublicKey, c *cache.Cache) (bool, error) {
	publicKey, err := GetKeyHandle(ctx, session, key.Kid, PUBLIC_KEY, c)
	if err != nil {
		return false, fmt.Errorf("Public key not found [%s]", err)
	}

	var mechanism []*pkcs11.Mechanism
	var sig []byte
	switch key.Alg {
	case ALG_ECDSA:
		mechanism = ckm_ec
		var bs bytes.Buffer
		bs.Write(r.Bytes())
		bs.Write(s.Bytes())
		sig = bs.Bytes()
	case ALG_SM2:
		mechanism = ckm_sm2_sign_verify
		sig, err = MarshalSignature(r, s)
		if err != nil {
			return false, fmt.Errorf("MarshalSignature failed [%s]", err)
		}
	default:
		return false, fmt.Errorf("Unsupported alg")
	}

	err = ctx.VerifyInit(session, mechanism, *publicKey)
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify-initialize [%s]", err)
	}
	err = ctx.Verify(session, msg, sig)
	if err == pkcs11.Error(pkcs11.CKR_SIGNATURE_INVALID) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("PKCS11: Verify failed [%s]", err)
	}

	return true, nil
}

//加密
func Encrypt(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, msg []byte, key *PublicKey, c *cache.Cache) (enc []byte, err error) {
	pubKey, err := GetKeyHandle(ctx, session, key.Kid, PUBLIC_KEY, c)
	if err != nil {
		return nil, fmt.Errorf("Public key not found [%s]", err)
	}

	var mechanism []*pkcs11.Mechanism

	switch key.Alg {
	case ALG_ECDSA:
		mechanism = ckm_ec
	case ALG_SM2:
		mechanism = ckm_sm2_enc_dec
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}

	err = ctx.EncryptInit(session, mechanism, *pubKey)
	if err != nil {
		return nil, fmt.Errorf("Encrypt-initialize  failed [%s]", err)
	}

	enc, err = ctx.Encrypt(session, msg)
	if err != nil {
		return nil, fmt.Errorf("P11: encrypt failed [%s]", err)
	}

	return enc, nil
}

//解密
func Decrypt(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, enc []byte, key *PrivateKey, c *cache.Cache) (dec []byte, err error) {
	priKey, err := GetKeyHandle(ctx, session, key.Kid, PRIVATE_KEY, c)
	if err != nil {
		return nil, fmt.Errorf("Private key not found [%s]", err)
	}

	var mechanism []*pkcs11.Mechanism

	switch key.Alg {
	case ALG_ECDSA:
		mechanism = ckm_ec
	case ALG_SM2:
		mechanism = ckm_sm2_enc_dec
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}

	err = ctx.DecryptInit(session, mechanism, *priKey)
	if err != nil {
		return nil, fmt.Errorf("Decrypt-initialize  failed [%s]", err)
	}

	dec, err = ctx.Decrypt(session, enc)
	if err != nil {
		return nil, fmt.Errorf("P11: decrypt failed [%s]", err)
	}

	return dec, nil
}
