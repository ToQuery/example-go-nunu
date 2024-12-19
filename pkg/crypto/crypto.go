// package crypto
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"example-go-nunu/pkg/log"
	"fmt"
	"github.com/spf13/viper"
	"io"
	"strings"
)

// Crypto 工具类
type Crypto struct {
	logger        *log.Logger
	aesKey        string
	rsaPublicKey  *rsa.PublicKey
	rsaPrivateKey *rsa.PrivateKey
}

func NewCrypto(conf *viper.Viper, logger *log.Logger) *Crypto {
	crypto := &Crypto{
		logger: logger,
	}

	aesKey := conf.GetString("security.api_encrypt.aes_key")
	if aesKey != "" {
		crypto.aesKey = aesKey
	}

	rsaPublicKey := conf.GetString("security.api_encrypt.rsa_public_key")
	rsaPrivateKey := conf.GetString("security.api_encrypt.rsa_private_key")

	if rsaPublicKey != "" && rsaPrivateKey != "" {
		publicKey, err := LoadPublicKeyFromConfig(rsaPublicKey)
		if err != nil {
			panic(err)
		}
		crypto.rsaPublicKey = publicKey
		privateKey, err := LoadPrivateKeyFromConfig(rsaPrivateKey)
		if err != nil {
			panic(err)
		}
		crypto.rsaPrivateKey = privateKey
	}

	return crypto
}

// 从配置中加载公钥
func LoadPublicKeyFromConfig(publicKeyString string) (*rsa.PublicKey, error) {
	publicKeyPEM := []byte(publicKeyString)

	block, _ := pem.Decode(publicKeyPEM)
	if block == nil || block.Type != "PUBLIC KEY" {
		return nil, errors.New("公钥文件格式错误")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("公钥类型错误")
	}

	return rsaPublicKey, nil
}

// 从配置中加载私钥
func LoadPrivateKeyFromConfig(privateKeyString string) (*rsa.PrivateKey, error) {
	privateKeyPEM := []byte(privateKeyString)

	block, _ := pem.Decode(privateKeyPEM)
	if block == nil || block.Type != "RSA PRIVATE KEY" {
		return nil, fmt.Errorf("私钥文件格式错误")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPrivateKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("私钥类型错误")
	}
	return rsaPrivateKey, nil
}

// Encrypt 使用公钥加密数据
func (r *Crypto) RSAEncrypt(data interface{}) string {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return ""
	}
	encryptedBytes, err := rsa.EncryptPKCS1v15(rand.Reader, r.rsaPublicKey, jsonData)
	if err != nil {
		return ""
	}
	return base64.StdEncoding.EncodeToString(encryptedBytes)
}

// Decrypt 使用私钥解密数据
func (r *Crypto) RSADecrypt(data string) string {
	dataByte, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return ""
	}
	decryptedBytes, err := rsa.DecryptPKCS1v15(rand.Reader, r.rsaPrivateKey, dataByte)
	if err != nil {
		return ""
	}
	return string(decryptedBytes)
}

// AES 加密
func (r *Crypto) AESEncrypt(data interface{}) (string, error) {
	// 将数据转换为 JSON 字符串
	plainText, err := json.Marshal(data)
	if err != nil {
		return "", err
	}

	// AES-256 密钥长度为 32 字节
	key := []byte(r.aesKey)
	if len(key) != 32 {
		return "", errors.New("AES key length must be 256 bits (32 bytes)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 填充数据到 AES 块大小
	plainText = AESPad(plainText, block.BlockSize())

	// cipherText 包含 IV 和加密后的内容
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	// 生成随机 IV
	iv := cipherText[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	// 使用 CBC 模式加密
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText[aes.BlockSize:], plainText)

	// 返回 IV 和加密后的密文，转换为十六进制字符串并用冒号分隔
	return fmt.Sprintf("%s:%s", hex.EncodeToString(iv), hex.EncodeToString(cipherText[aes.BlockSize:])), nil
}

// AES 解密
func (r *Crypto) AESDecrypt(encryptedText string) (string, error) {
	// 将冒号分隔的 IV 和加密数据分离
	parts := strings.Split(encryptedText, ":")
	if len(parts) != 2 {
		return "", errors.New("invalid encrypted data format")
	}
	ivHex, cipherTextHex := parts[0], parts[1]

	// 将 IV 和密文分别转换为字节数组
	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return "", err
	}
	cipherText, err := hex.DecodeString(cipherTextHex)
	if err != nil {
		return "", err
	}

	// AES-256 密钥长度为 32 字节
	key := []byte(r.aesKey)
	if len(key) != 32 {
		return "", errors.New("AES key length must be 256 bits (32 bytes)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	// 使用 CBC 模式解密
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(cipherText, cipherText)

	// 去除填充
	unpaddedText, err := AESUnpad(cipherText)
	if err != nil {
		return "", err
	}

	// 返回解密后的字符串
	return string(unpaddedText), nil
}

// AES 填充，使用 PKCS5 填充（等同于 PKCS7）
func AESPad(src []byte, blockSize int) []byte {
	padding := blockSize - len(src)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(src, padtext...)
}

// AES 去填充
func AESUnpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 {
		return nil, errors.New("invalid padding size")
	}
	padding := int(src[length-1])
	if padding > length || padding > aes.BlockSize {
		return nil, errors.New("invalid padding size")
	}
	return src[:length-padding], nil
}

func main() {
	// 创建 Crypto 实例，AES-256 密钥必须为 32 字节
	crypto := Crypto{aesKey: "UWZccNCS8x4WAYJaHxuirso1KOgjBK1V"}

	// 测试数据
	data := map[string]string{
		"username": "admin",
		"password": "password123",
	}

	// AES 加密
	encrypted, err := crypto.AESEncrypt(data)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}
	fmt.Println("Encrypted:", encrypted)

	// AES 解密
	decrypted, err := crypto.AESDecrypt(encrypted)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}
	fmt.Println("Decrypted:", decrypted)
}
