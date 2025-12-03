package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Encryptor обеспечивает шифрование данных
type Encryptor struct {
	masterKey []byte
	aead      cipher.AEAD
}

// NewEncryptor создает новый шифратор
func NewEncryptor() *Encryptor {
	return &Encryptor{}
}

// Encrypt шифрует данные с использованием пароля
func (e *Encryptor) Encrypt(data interface{}, password string) ([]byte, error) {
	// Сериализуем данные в JSON
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %v", err)
	}

	// Генерируем соль
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %v", err)
	}

	// Генерируем ключ из пароля
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Создаем AEAD с использованием XChaCha20-Poly1305
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	// Генерируем nonce
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(jsonData)+aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Шифруем данные
	ciphertext := aead.Seal(nonce, nonce, jsonData, nil)

	// Добавляем соль в начало
	encryptedData := append(salt, ciphertext...)

	return encryptedData, nil
}

// Decrypt расшифровывает данные с использованием пароля
func (e *Encryptor) Decrypt(encryptedData []byte, password string) ([]byte, error) {
	if len(encryptedData) < 16 {
		return nil, errors.New("encrypted data too short")
	}

	// Извлекаем соль
	salt := encryptedData[:16]
	ciphertext := encryptedData[16:]

	// Генерируем ключ из пароля
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Создаем AEAD
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AEAD: %v", err)
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}

	// Извлекаем nonce
	nonce, ciphertext := ciphertext[:aead.NonceSize()], ciphertext[aead.NonceSize():]

	// Расшифровываем данные
	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// TryDecrypt пытается расшифровать данные, сначала без пароля
func (e *Encryptor) TryDecrypt(data []byte, password string) ([]byte, error) {
	// Сначала пытаемся расшифровать без пароля (если данные не зашифрованы)
	if isJSON(data) {
		return data, nil
	}

	// Если указан пароль, пытаемся расшифровать
	if password != "" {
		return e.Decrypt(data, password)
	}

	// Если пароль не указан, но данные зашифрованы, возвращаем ошибку
	return nil, errors.New("data is encrypted, password required")
}

// EncryptString шифрует строку
func (e *Encryptor) EncryptString(text, password string) (string, error) {
	encrypted, err := e.Encrypt([]byte(text), password)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

// DecryptString расшифровывает строку
func (e *Encryptor) DecryptString(encryptedText, password string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedText)
	if err != nil {
		return "", err
	}

	decrypted, err := e.Decrypt(encrypted, password)
	if err != nil {
		return "", err
	}

	return string(decrypted), nil
}

// GenerateKeyPair генерирует пару ключей для WireGuard
func (e *Encryptor) GenerateKeyPair() (privateKey, publicKey string, err error) {
	// Генерируем приватный ключ
	privateKeyBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, privateKeyBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %v", err)
	}

	// Конвертируем в base64
	privateKey = base64.StdEncoding.EncodeToString(privateKeyBytes)

	// Генерируем публичный ключ (упрощенно)
	// В реальном приложении используйте криптографию Curve25519
	publicKeyBytes := sha256.Sum256(privateKeyBytes)
	publicKey = base64.StdEncoding.EncodeToString(publicKeyBytes[:])

	return privateKey, publicKey, nil
}

// HashPassword создает хеш пароля
func (e *Encryptor) HashPassword(password string) (string, error) {
	// Генерируем соль
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Создаем хеш с использованием Argon2
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Комбинируем соль и хеш
	result := make([]byte, len(salt)+len(hash))
	copy(result, salt)
	copy(result[len(salt):], hash)

	return base64.StdEncoding.EncodeToString(result), nil
}

// VerifyPassword проверяет пароль
func (e *Encryptor) VerifyPassword(password, hashedPassword string) bool {
	// Декодируем хеш
	decoded, err := base64.StdEncoding.DecodeString(hashedPassword)
	if err != nil || len(decoded) < 16 {
		return false
	}

	// Извлекаем соль и хеш
	salt := decoded[:16]
	storedHash := decoded[16:]

	// Вычисляем хеш от предоставленного пароля
	computedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Сравниваем хеши
	if len(computedHash) != len(storedHash) {
		return false
	}

	for i := 0; i < len(computedHash); i++ {
		if computedHash[i] != storedHash[i] {
			return false
		}
	}

	return true
}

// GenerateOTPSecret генерирует секрет для двухфакторной аутентификации
func (e *Encryptor) GenerateOTPSecret() (string, error) {
	secret := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, secret); err != nil {
		return "", fmt.Errorf("failed to generate OTP secret: %v", err)
	}

	return base32.StdEncoding.EncodeToString(secret), nil
}

// BackupKeys создает резервную копию ключей
func (e *Encryptor) BackupKeys(keys map[string]string, backupPassword string) ([]byte, error) {
	// Сериализуем ключи
	keysJSON, err := json.Marshal(keys)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal keys: %v", err)
	}

	// Шифруем резервную копию
	return e.Encrypt(keysJSON, backupPassword)
}

// RestoreKeys восстанавливает ключи из резервной копии
func (e *Encryptor) RestoreKeys(backupData []byte, backupPassword string) (map[string]string, error) {
	// Расшифровываем резервную копию
	decrypted, err := e.Decrypt(backupData, backupPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt backup: %v", err)
	}

	// Десериализуем ключи
	var keys map[string]string
	if err := json.Unmarshal(decrypted, &keys); err != nil {
		return nil, fmt.Errorf("failed to unmarshal keys: %v", err)
	}

	return keys, nil
}

// Helper functions

func isJSON(data []byte) bool {
	var js json.RawMessage
	return json.Unmarshal(data, &js) == nil
}

// base32 кодирование (упрощенно)
var base32 = base32.NewEncoding("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567").WithPadding(base32.NoPadding)
