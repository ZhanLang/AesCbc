package AesCbc

import (
	"encoding/base64"

	"crypto/aes"
	"crypto/cipher"
	"bytes"

)


func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}
func PKCS7UnPadding(plantText []byte, blockSize int) []byte {
	length := len(plantText)
	unpadding := int(plantText[length-1])
	return plantText[:(length - unpadding)]
}

func EncryptionAES( key string, vi string , in []byte) (string , error) {
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	in = PKCS7Padding(in, block.BlockSize())
	blockModel := cipher.NewCBCEncrypter(block, []byte(vi))
	ciphertext := make([]byte, len(in))
	blockModel.CryptBlocks(ciphertext, in)
	return base64.StdEncoding.EncodeToString(ciphertext), nil;
}

func DecryptionAES( key string, vi string , value string) ([]byte , error) {
	block, err := aes.NewCipher([]byte( key ))
	if err != nil {
		return nil, err
	}

	ciphertext , err:= base64.StdEncoding.DecodeString( value );
	if err != nil {
		 return nil, err;
	}

	blockModel := cipher.NewCBCDecrypter(block, []byte( vi ))
	plantText := make([]byte, len(ciphertext))
	blockModel.CryptBlocks(plantText, ciphertext)
	plantText = PKCS7UnPadding(plantText, block.BlockSize())
	return plantText,nil;
}