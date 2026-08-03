package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
)

func SecureStore(contract interface{}, key []byte, path string) (string, error) {
	// 1. Marshal contract
	data, err := json.Marshal(contract)
	if err != nil {
		return "", err
	}

	// 2. Hash → Contract ID
	hash := sha256.Sum256(data)
	contractID := hex.EncodeToString(hash[:])

	// 3. AES Cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	io.ReadFull(rand.Reader, nonce)

	// 4. Encrypt
	ciphertext := gcm.Seal(nonce, nonce, data, nil)

	// 5. Write file
	file := path + contractID + ".bin"
	err = os.WriteFile(file, ciphertext, 0600)
	if err != nil {
		return "", err
	}

	return contractID, nil
}
