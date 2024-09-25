package aesextension

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/sha1"
    "encoding/base64"
    "strings"

    "github.com/k6io/k6/js/modules"
)

// Register AES extension as a k6 module
func init() {
    modules.Register("k6/x/aesextension", new(AESModule))
}

type AESModule struct{}

// Helper function to derive a 16-byte key using SHA-1
func deriveKey(secret string) []byte {
    hasher := sha1.New()
    hasher.Write([]byte(secret))
    key := hasher.Sum(nil)
    return key[:16] // Use first 16 bytes
}

// PKCS5Padding pads plaintext to a multiple of block size
func PKCS5Padding(plainText []byte, blockSize int) []byte {
    padding := blockSize - len(plainText)%blockSize
    padText := bytes.Repeat([]byte{byte(padding)}, padding)
    return append(plainText, padText...)
}

// PKCS5Unpadding removes padding from decrypted text
func PKCS5Unpadding(plainText []byte) []byte {
    length := len(plainText)
    unpadding := int(plainText[length-1])
    return plainText[:(length - unpadding)]
}

// EncryptAES encrypts using AES/ECB/PKCS5Padding
func (m *AESModule) EncryptAES(plainText string, secret string) (string, error) {
    key := deriveKey(secret)
    
    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    plainTextBytes := []byte(plainText)
    plainTextBytes = PKCS5Padding(plainTextBytes, block.BlockSize())

    cipherText := make([]byte, len(plainTextBytes))

    for i := 0; i < len(plainTextBytes); i += block.BlockSize() {
        block.Encrypt(cipherText[i:i+block.BlockSize()], plainTextBytes[i:i+block.BlockSize()])
    }

    return base64.StdEncoding.EncodeToString(cipherText), nil
}

// DecryptAES decrypts using AES/ECB/PKCS5Padding
func (m *AESModule) DecryptAES(cipherText string, secret string) (string, error) {
    key := deriveKey(secret)

    block, err := aes.NewCipher(key)
    if err != nil {
        return "", err
    }

    cipherTextBytes, err := base64.StdEncoding.DecodeString(cipherText)
    if err != nil {
        return "", err
    }

    plainText := make([]byte, len(cipherTextBytes))

    for i := 0; i < len(cipherTextBytes); i += block.BlockSize() {
        block.Decrypt(plainText[i:i+block.BlockSize()], cipherTextBytes[i:i+block.BlockSize()])
    }

    plainText = PKCS5Unpadding(plainText)
    return string(plainText), nil
}
