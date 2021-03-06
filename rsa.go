package encrypt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

type RSA struct {
	PrivateKey []byte
	PublicKey  []byte
}

func NewRsa() *RSA {
	return &RSA{}
}

//设置公钥
func (r *RSA) SetPublicKey(publicKey []byte) {
	r.PublicKey = publicKey
}

//私钥
func (r *RSA) SetPrivateKey(privateKey []byte) {
	r.PrivateKey = privateKey
}

// 加密
func (r *RSA) Encrypt(origData []byte) ([]byte, error) {
	//解密pem格式的公钥
	block, _ := pem.Decode(r.PublicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	// 解析公钥
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 类型断言
	pub := pubInterface.(*rsa.PublicKey)
	//加密
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}

// 解密
func (r *RSA) Decrypt(ciphertext []byte) ([]byte, error) {
	//解密
	block, _ := pem.Decode(r.PrivateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	// 解密
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
