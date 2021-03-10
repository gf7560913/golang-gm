package engine

import (
	"bytes"
	"crypto/cipher"
	"crypto/engine/pkcs11"
	"crypto/sm3"
	//"encoding/hex"
	"fmt"
)

const BlockSize = 16

type p11Cipher struct {
	Kid    []byte
	Alg    int
	Key    []byte
	IV     []byte
	Engine Engine
}

func NewCipher(alg int, key, iv []byte, isEphemeral bool, e *Engine) (cipher.Block, error) {
	session := e.GetSession()
	defer e.ReturnSession(session)
	key_t := append(sym_key_t, pkcs11.NewAttribute(pkcs11.CKA_TOKEN, isEphemeral), pkcs11.NewAttribute(pkcs11.CKA_VALUE, key))
	//var mechanism []*pkcs11.Mechanism
	switch alg {
	case ALG_SM4:
		key_t = append(key_t, key_type_sm4, pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 16))
		//mechanism = ckm_sm4_key_gen
	case ALG_AES:
		key_t = append(key_t, key_type_aes, pkcs11.NewAttribute(pkcs11.CKA_VALUE_LEN, 32))
		//mechanism = ckm_aes_key_gen
	default:
		return nil, fmt.Errorf("Unsupported alg")
	}
	keyObj, err := e.Ctx.CreateObject(session, key_t)
	if err != nil {
		return nil, err
	}
	_, err = getCKAValue(e.Ctx, session, keyObj)
	if err != nil {
		return nil, err
	}
	hash := sm3.Sm3Sum(key)
	kid := hash[:]
	setkid_t := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, kid),
		//pkcs11.NewAttribute(pkcs11.CKA_LABEL, hex.EncodeToString(kid)),
	}
	err = e.Ctx.SetAttributeValue(session, keyObj, setkid_t)
	if err != nil {
		return nil, fmt.Errorf("P11: set-ID-to-KID[Symkey] failed [%s]", err)
	}

	return &p11Cipher{kid, alg, key, iv, *e}, nil
}

func (c *p11Cipher) BlockSize() int {
	return BlockSize
}

func GetSymKey(id []byte, e *Engine) ([]byte, error) {
	session := e.GetSession()
	defer e.ReturnSession(session)
	hash := sm3.Sm3Sum(id)
	kid := hash[:]
	key, err := findKeyByKid(e.Ctx, session, kid, SYM_KEY)
	if err != nil {
		return nil, err
	}

	return getCKAValue(e.Ctx, session, *key)
}

func (c *p11Cipher) Encrypt(dst, src []byte) {
	session := c.Engine.GetSession()
	defer c.Engine.ReturnSession(session)
	EncryptECB(c.Engine.Ctx, session, dst, src, c.IV, c.Kid, c.Alg)
}

func (c *p11Cipher) Decrypt(dst, src []byte) {
	session := c.Engine.GetSession()
	defer c.Engine.ReturnSession(session)
	DecryptECB(c.Engine.Ctx, session, dst, src, c.IV, c.Kid, c.Alg)
}

func EncryptCBC(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, dst, src, iv, kid []byte, alg int) {
	key, err := findKeyByKid(ctx, session, kid, SYM_KEY)
	if err != nil {
		dst = nil
	}

	var mechanism []*pkcs11.Mechanism
	switch alg {
	case ALG_SM4:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_CBC, iv)}
	case ALG_AES:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv)}
	default:
		dst = nil
	}
	err = ctx.EncryptInit(session, mechanism, *key)
	if err != nil {
		dst = nil
	}

	enc, err := ctx.Encrypt(session, src)
	if err != nil {
		dst = nil
	}
	copy(dst, enc)
}

func DecryptCBC(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, dst, src, iv, kid []byte, alg int) {
	key, err := findKeyByKid(ctx, session, kid, SYM_KEY)
	if err != nil {
		dst = nil
	}
	var mechanism []*pkcs11.Mechanism
	switch alg {
	case ALG_SM4:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_CBC, iv)}
	case ALG_AES:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, iv)}
	default:
		dst = nil
	}
	err = ctx.DecryptInit(session, mechanism, *key)
	if err != nil {
		dst = nil
	}

	dec, err := ctx.Decrypt(session, src)
	if err != nil {
		dst = nil
	}
	copy(dst, dec)
}

func EncryptECB(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, dst, src, iv, kid []byte, alg int) {
	key, err := findKeyByKid(ctx, session, kid, SYM_KEY)
	if err != nil {
		dst = nil
	}

	var mechanism []*pkcs11.Mechanism
	switch alg {
	case ALG_SM4:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_ECB, nil)}
	case ALG_AES:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_ECB, nil)}
	default:
		dst = nil
	}
	err = ctx.EncryptInit(session, mechanism, *key)
	if err != nil {
		dst = nil
	}

	enc, err := ctx.Encrypt(session, src)
	if err != nil {
		dst = nil
	}
	//dst = enc
	copy(dst, enc)
}

func DecryptECB(ctx *pkcs11.Ctx, session pkcs11.SessionHandle, dst, src, iv, kid []byte, alg int) {
	key, err := findKeyByKid(ctx, session, kid, SYM_KEY)
	if err != nil {
		dst = nil
	}
	var mechanism []*pkcs11.Mechanism
	switch alg {
	case ALG_SM4:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_ECB, nil)}
	case ALG_AES:
		mechanism = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}
	default:
		dst = nil
	}
	err = ctx.DecryptInit(session, mechanism, *key)
	if err != nil {
		dst = nil
	}

	dec, err := ctx.Decrypt(session, src)
	if err != nil {
		dst = nil
	}
	//dst = dec
	copy(dst, dec)
}

func PKCS7Padding(src []byte) []byte {
	padding := BlockSize - len(src)%BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

func PKCS7UnPadding(src []byte) ([]byte, error) {
	length := len(src)
	unpadding := int(src[length-1])

	if unpadding > BlockSize || unpadding == 0 {
		return nil, fmt.Errorf("Invalid pkcs7 padding (unpadding > aes.BlockSize || unpadding == 0)")
	}

	pad := src[len(src)-unpadding:]
	for i := 0; i < unpadding; i++ {
		if pad[i] != byte(unpadding) {
			return nil, fmt.Errorf("Invalid pkcs7 padding (pad[i] != unpadding)")
		}
	}

	return src[:(length - unpadding)], nil
}
