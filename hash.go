package encrypt

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
)

//md5加密
func Md5(s string) string {
	m := md5.New()
	m.Write([]byte(s))
	return hex.EncodeToString(m.Sum(nil))
}

// HMAC是密钥相关的哈希运算消息认证码（Hash-based Message Authentication Code）的缩写
//它通过一个标准算法，在计算哈希的过程中，把key混入计算过程中
//k随意设置 d 要加密数据
func Hmac(k, d string) string {
	h := hmac.New(md5.New, []byte(k)) // create md5
	h.Write([]byte(d))
	return hex.EncodeToString(h.Sum([]byte("")))
}

func HmacSha256(k, d string) string {
	h := hmac.New(sha256.New, []byte(k)) //create sha256
	h.Write([]byte(d))
	return hex.EncodeToString(h.Sum([]byte("")))
}

//SHA-1可以生成一个被称为消息摘要的160位（20字节）散列值，散列值通常的呈现形式为40个十六进制数
func Sha1(d string) string {
	sh := sha1.New()
	sh.Write([]byte(d))
	return hex.EncodeToString(sh.Sum([]byte("")))
}
