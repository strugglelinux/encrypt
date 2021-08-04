# 加密 解密算法

>数字签名：数字签名是非对称密钥加密技术与数字摘要技术的应用。主要算法有md5、hmac、sha1等。

``` go
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
 ```

## AES

 高级加密标准（Advanced Encryption Standard，AES) 又称Rijndael加密法
 AES中常见的有三种解决方案，分别为AES-128、AES-192和AES-256。如果采用真正的128位加密技术甚至256位加密技术，蛮力攻击要取得成功需要耗费相当长的时间
 AES 有五种加密模式：
> 电码本模式（Electronic Codebook Book (ECB)）
> 密码分组链接模式（Cipher Block Chaining (CBC)）
> 计算器模式（Counter (CTR)）
> 密码反馈模式（Cipher FeedBack (CFB)）
> 输出反馈模式（Output FeedBack (OFB)）

```go
    //Ecb = 1 //电码本模式
    //Cbc = 2 //密码分组链接模式
    //Ctr = 3 //计算器模式
    //Cfb = 4 //密码反馈模式
    //Ofb = 5 //输出反馈模式
    src := []byte("hello world")
    key := []byte("1443flfsaWfdas12")
    aes:= NewAES() // 默认是Cbc 模式
    aes.SetMode(Ecb)
    got, err := aes.Encrypt(src, key) 
    want, err := a.Decrypt(got, key)

```

### RSA

```go
    privateKey := []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQDcGsUIIAINHfRTdMmgGwLrjzfMNSrtgIf4EGsNaYwmC1GjF/bM
h0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdTnCDPPZ7oV7p1B9Pud+6zPaco
qDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Zy682X1+R1lRK8D+vmQIDAQAB
AoGAeWAZvz1HZExca5k/hpbeqV+0+VtobMgwMs96+U53BpO/VRzl8Cu3CpNyb7HY
64L9YQ+J5QgpPhqkgIO0dMu/0RIXsmhvr2gcxmKObcqT3JQ6S4rjHTln49I2sYTz
7JEH4TcplKjSjHyq5MhHfA+CV2/AB2BO6G8limu7SheXuvECQQDwOpZrZDeTOOBk
z1vercawd+J9ll/FZYttnrWYTI1sSF1sNfZ7dUXPyYPQFZ0LQ1bhZGmWBZ6a6wd9
R+PKlmJvAkEA6o32c/WEXxW2zeh18sOO4wqUiBYq3L3hFObhcsUAY8jfykQefW8q
yPuuL02jLIajFWd0itjvIrzWnVmoUuXydwJAXGLrvllIVkIlah+lATprkypH3Gyc
YFnxCTNkOzIVoXMjGp6WMFylgIfLPZdSUiaPnxby1FNM7987fh7Lp/m12QJAK9iL
2JNtwkSR3p305oOuAz0oFORn8MnB+KFMRaMT9pNHWk0vke0lB1sc7ZTKyvkEJW0o
eQgic9DvIYzwDUcU8wJAIkKROzuzLi9AvLnLUrSdI6998lmeYO9x7pwZPukz3era
zncjRK3pbVkv0KrKfczuJiRlZ7dUzVO0b6QJr8TRAA==
-----END RSA PRIVATE KEY-----
`)

	// 公钥: 根据私钥生成
	//openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem
	publicKey := []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDcGsUIIAINHfRTdMmgGwLrjzfM
NSrtgIf4EGsNaYwmC1GjF/bMh0Mcm10oLhNrKNYCTTQVGGIxuc5heKd1gOzb7bdT
nCDPPZ7oV7p1B9Pud+6zPacoqDz2M24vHFWYY2FbIIJh8fHhKcfXNXOLovdVBE7Z
y682X1+R1lRK8D+vmQIDAQAB
-----END PUBLIC KEY-----
`)

	source := "hello world"
	ras := &RSA{}
	ras.SetPrivateKey(privateKey)
	ras.SetPublicKey(publicKey)
	data, _ := ras.Encrypt([]byte(source))
	origData, _ := ras.Decrypt(data)
```


参考：  [Go 加密解密算法总结](https://mp.weixin.qq.com/s/fMroAYNPGI80MDqLbcenyQ)  