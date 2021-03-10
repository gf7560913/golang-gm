package engine

//算法常量
const (
	ALG_SM1   = 1
	ALG_SM2   = 2
	ALG_SM3   = 3
	ALG_SM4   = 4
	ALG_ECDSA = 5
	ALG_RSA   = 6
	ALG_AES   = 7
)

//秘钥类型常量
const (
	PUBLIC_KEY  = "pub"
	PRIVATE_KEY = "prv"
	SYM_KEY     = "sym"
)

//对称加密填充模式
const (
	ECB = "ecb"
	CBC = "cbc"
)
