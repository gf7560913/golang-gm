package engine

import (
	"crypto/engine/pkcs11"
)

//公钥基础模板
var pubkey_base_t = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PUBLIC_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_VERIFY, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, false),
}

//私钥基础模板
var prvkey_base_t = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_PRIVATE_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_SIGN, true),
	pkcs11.NewAttribute(pkcs11.CKA_PRIVATE, true),
}

//对称秘钥基础模板
var sym_key_t = []*pkcs11.Attribute{
	pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_SECRET_KEY),
	pkcs11.NewAttribute(pkcs11.CKA_ENCRYPT, true),
	pkcs11.NewAttribute(pkcs11.CKA_DECRYPT, true),
}

/********SM2********/
//SM2秘钥类型属性
var key_type_sm2 = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SM2)

//SM2密钥对产生机制
var ckm_sm2_key_pair_gen = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM2_KEY_PAIR_GEN, nil)}

//SM2签名验签机制
var ckm_sm2_sign_verify = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM3_SM2, nil)}

//SM2加密解密机制
var ckm_sm2_enc_dec = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM2_RAW, nil)}

/********SM3********/

/********SM4********/
//SM4秘钥类型属性
var key_type_sm4 = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_SM4)

//SM4秘钥产生机制
var ckm_sm4_key_gen = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_KEY_GEN, nil)}

//SM4加密解密机制
var ckm_sm4_ecb = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_ECB, nil)}
var ckm_sm4_cbc = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_SM4_CBC, nil)}

/********EC********/
//EC秘钥类型属性
var key_type_ec = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_EC)

//EC密钥对产生机制
var ckm_ec_key_pair_gen = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_EC_KEY_PAIR_GEN, nil)}

//ECDSA签名验签加密解密机制
var ckm_ec = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_ECDSA, nil)}

/********AES********/
//AES秘钥类型属性
var key_type_aes = pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, pkcs11.CKK_AES)

//AES秘钥产生机制
var ckm_aes_key_gen = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_KEY_GEN, nil)}

//SM4加密解密机制
var ckm_aes_ecb = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_ECB, nil)}
var ckm_aes_cbc = []*pkcs11.Mechanism{pkcs11.NewMechanism(pkcs11.CKM_AES_CBC, nil)}
