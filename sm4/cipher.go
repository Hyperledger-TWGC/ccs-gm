package sm4

import (
	"crypto/cipher"
	"strconv"
)

type sm4Cipher struct{
	enc []uint32
	dec []uint32
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/sm4: invalid key size " + strconv.Itoa(int(k))
}

func NewCipher(key []byte) (cipher.Block,error){
	k := len(key)
	if k != BlockSize{
		return nil, KeySizeError(k)
	}
	cipher :=  &sm4Cipher{
		enc: make([]uint32, 32),
		dec: make([]uint32, 32),
	}
	expandKey(key, cipher.enc, cipher.dec)
	return cipher,nil
}

func (c *sm4Cipher) BlockSize() int {
	return BlockSize
}

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	encryptBlock(c.enc, dst, src)
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	encryptBlock(c.dec, dst, src)
}