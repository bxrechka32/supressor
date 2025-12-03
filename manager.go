package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"time"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/argon2"

	"supressor/internal/config"
	"supressor/internal/storage"
	"supressor/internal/utils"
)

// Manager управляет аутентификацией и авторизацией
type Manager struct {
	config      *config.Config
	db          *storage.Database
	sessions    map[string]*Session
	tokens      map[string]*Token
	mfa         *MFAManager
	biometrics  *BiometricManager
	rateLimiter *RateLimiter
	logger      *utils.Logger
	mu          sync.RWMutex
}

// User представляет пользователя
type User struct {
	ID              string    `json:"id"`
	Username        string    `json:"username"`
	Email           string    `json:"email"`
	PasswordHash    string    `json:"password_hash"`
	DisplayName     string    `json:"display_name"`
	Avatar          string    `json:"avatar"`
	Role            string    `json:"role"` // admin, user, guest
	Permissions     []string  `json:"permissions"`
	MFASecret       string    `json:"mfa_secret"`
	MFAEnabled      bool      `json:"mfa_enabled"`
	BackupCodes     []string  `json:"backup_codes"`
	LastLogin       time.Time `json:"last_login"`
	FailedAttempts  int       `json:"failed_attempts"`
	LockedUntil     time.Time `json:"locked_until"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	IsActive        bool      `json:"is_active"`
	SecurityAnswers map[string]string `json:"security_answers"`
	TrustedDevices  []TrustedDevice   `json:"trusted_devices"`
}

// Session представляет сессию пользователя
type Session struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	Token        string    `json:"token"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	ExpiresAt    time.Time `json:"expires_at"`
	IsValid      bool      `json:"is_valid"`
	DeviceInfo   DeviceInfo `json:"device_info"`
}

// Token представляет токен доступа
type Token struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Token       string    `json:"token"`
	Type        string    `json:"type"` // access, refresh, api
	Scope       []string  `json:"scope"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	IsRevoked   bool      `json:"is_revoked"`
}

// TrustedDevice представляет доверенное устройство
type TrustedDevice struct {
	ID           string    `json:"id"`
	UserID       string    `json:"user_id"`
	DeviceID     string    `json:"device_id"`
	DeviceName   string    `json:"device_name"`
	DeviceType   string    `json:"device_type"`
	Fingerprint  string    `json:"fingerprint"`
	LastUsed     time.Time `json:"last_used"`
	CreatedAt    time.Time `json:"created_at"`
	IsTrusted    bool      `json:"is_trusted"`
}

// DeviceInfo содержит информацию об устройстве
type DeviceInfo struct {
	OS          string `json:"os"`
	Browser     string `json:"browser"`
	Device      string `json:"device"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	UserAgent   string `json:"user_agent"`
}

// NewManager создает новый менеджер аутентификации
func NewManager(cfg *config.Config, db *storage.Database) *Manager {
	logger := utils.NewLogger("auth")

	return &Manager{
		config:      cfg,
		db:          db,
		sessions:    make(map[string]*Session),
		tokens:      make(map[string]*Token),
		mfa:         NewMFAManager(),
		biometrics:  NewBiometricManager(),
		rateLimiter: NewRateLimiter(),
		logger:      logger,
	}
}

// Register регистрирует нового пользователя
func (m *Manager) Register(username, email, password string) (*User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверка существования пользователя
	if exists, _ := m.db.UserExists(username, email); exists {
		return nil, fmt.Errorf("user already exists")
	}

	// Валидация пароля
	if err := m.validatePassword(password); err != nil {
		return nil, err
	}

	// Хеширование пароля
	passwordHash, err := m.hashPassword(password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Создание пользователя
	user := &User{
		ID:           generateUserID(),
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		DisplayName:  username,
		Role:         "user",
		Permissions:  []string{"read", "write"},
		MFAEnabled:   false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
		IsActive:     true,
	}

	// Сохранение в БД
	if err := m.db.SaveUser(user); err != nil {
		return nil, fmt.Errorf("failed to save user: %v", err)
	}

	// Создание начальной сессии
	session, err := m.createSession(user.ID, "127.0.0.1", "CLI")
	if err != nil {
		m.logger.Error("Failed to create initial session", "error", err)
	}

	m.logger.Info("User registered", "username", username, "id", user.ID)
	return user, nil
}

// Login выполняет вход пользователя
func (m *Manager) Login(username, password, ipAddress, userAgent string) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверка ограничителя запросов
	if !m.rateLimiter.Allow(ipAddress, "login") {
		return nil, fmt.Errorf("too many login attempts")
	}

	// Получение пользователя
	user, err := m.db.GetUserByUsername(username)
	if err != nil {
		m.rateLimiter.Increment(ipAddress, "login")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Проверка блокировки аккаунта
	if user.LockedUntil.After(time.Now()) {
		return nil, fmt.Errorf("account is locked until %s", user.LockedUntil.Format(time.RFC1123))
	}

	// Проверка пароля
	if !m.verifyPassword(password, user.PasswordHash) {
		user.FailedAttempts++
		
		// Блокировка аккаунта при слишком многих попытках
		if user.FailedAttempts >= m.config.Security.MaxLoginAttempts {
			user.LockedUntil = time.Now().Add(30 * time.Minute)
			m.logger.Warn("Account locked", "username", username, "ip", ipAddress)
		}
		
		m.db.SaveUser(user)
		m.rateLimiter.Increment(ipAddress, "login")
		return nil, fmt.Errorf("invalid credentials")
	}

	// Сброс счетчика неудачных попыток
	user.FailedAttempts = 0
	user.LastLogin = time.Now()
	
	// Обновление пользователя
	if err := m.db.SaveUser(user); err != nil {
		return nil, fmt.Errorf("failed to update user: %v", err)
	}

	// Создание сессии
	session, err := m.createSession(user.ID, ipAddress, userAgent)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	m.logger.Info("User logged in", "username", username, "ip", ipAddress)
	return session, nil
}

// LoginWithMFA выполняет вход с двухфакторной аутентификацией
func (m *Manager) LoginWithMFA(username, password, code, ipAddress, userAgent string) (*Session, error) {
	// Сначала обычный логин
	session, err := m.Login(username, password, ipAddress, userAgent)
	if err != nil {
		return nil, err
	}

	// Получение пользователя
	user, err := m.db.GetUserByUsername(username)
	if err != nil {
		return nil, err
	}

	// Проверка MFA
	if user.MFAEnabled {
		if !m.mfa.Verify(code, user.MFASecret) {
			// Проверка backup кодов
			if !m.verifyBackupCode(code, user.BackupCodes) {
				return nil, fmt.Errorf("invalid MFA code")
			}
			// Удаление использованного backup кода
			m.removeBackupCode(code, user)
		}
	}

	return session, nil
}

// Logout выполняет выход пользователя
func (m *Manager) Logout(sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	session, exists := m.sessions[sessionID]
	if !exists {
		// Попробуем найти в БД
		session, err := m.db.GetSession(sessionID)
		if err != nil {
			return fmt.Errorf("session not found")
		}
		session.IsValid = false
		m.db.SaveSession(session)
		return nil
	}

	// Инвалидация сессии
	session.IsValid = false
	delete(m.sessions, sessionID)

	// Обновление в БД
	m.db.SaveSession(session)

	m.logger.Info("User logged out", "session_id", sessionID)
	return nil
}

// ValidateSession проверяет валидность сессии
func (m *Manager) ValidateSession(sessionID string) (*Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Проверка в памяти
	if session, exists := m.sessions[sessionID]; exists {
		if session.IsValid && session.ExpiresAt.After(time.Now()) {
			session.LastActivity = time.Now()
			return session, nil
		}
		// Удаление просроченной сессии
		delete(m.sessions, sessionID)
	}

	// Проверка в БД
	session, err := m.db.GetSession(sessionID)
	if err != nil {
		return nil, fmt.Errorf("invalid session")
	}

	if !session.IsValid || session.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("session expired")
	}

	// Обновление времени активности
	session.LastActivity = time.Now()
	m.db.SaveSession(session)

	// Кэширование в памяти
	m.sessions[sessionID] = session

	return session, nil
}

// GenerateToken генерирует новый токен
func (m *Manager) GenerateToken(userID, tokenType string, scope []string) (*Token, error) {
	token := &Token{
		ID:        generateTokenID(),
		UserID:    userID,
		Token:     generateSecureToken(),
		Type:      tokenType,
		Scope:     scope,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(24 * time.Hour), // 24 часа по умолчанию
		IsRevoked: false,
	}

	// Сохранение токена
	m.tokens[token.ID] = token
	m.db.SaveToken(token)

	return token, nil
}

// ValidateToken проверяет валидность токена
func (m *Manager) ValidateToken(tokenString string) (*Token, error) {
	// Поиск токена
	for _, token := range m.tokens {
		if token.Token == tokenString {
			if token.IsRevoked || token.ExpiresAt.Before(time.Now()) {
				return nil, fmt.Errorf("token invalid or expired")
			}
			return token, nil
		}
	}

	// Поиск в БД
	token, err := m.db.GetTokenByValue(tokenString)
	if err != nil {
		return nil, fmt.Errorf("token not found")
	}

	if token.IsRevoked || token.ExpiresAt.Before(time.Now()) {
		return nil, fmt.Errorf("token invalid or expired")
	}

	return token, nil
}

// RevokeToken отзывает токен
func (m *Manager) RevokeToken(tokenID string) error {
	token, exists := m.tokens[tokenID]
	if !exists {
		token, err := m.db.GetToken(tokenID)
		if err != nil {
			return fmt.Errorf("token not found")
		}
		token.IsRevoked = true
		m.db.SaveToken(token)
		return nil
	}

	token.IsRevoked = true
	m.db.SaveToken(token)

	return nil
}

// EnableMFA включает двухфакторную аутентификацию
func (m *Manager) EnableMFA(userID string) (string, []string, error) {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return "", nil, fmt.Errorf("user not found")
	}

	// Генерация секрета MFA
	secret, err := m.mfa.GenerateSecret(user.Email)
	if err != nil {
		return "", nil, fmt.Errorf("failed to generate MFA secret: %v", err)
	}

	// Генерация backup кодов
	backupCodes := m.generateBackupCodes()

	// Обновление пользователя
	user.MFASecret = secret
	user.MFAEnabled = true
	user.BackupCodes = backupCodes

	if err := m.db.SaveUser(user); err != nil {
		return "", nil, fmt.Errorf("failed to save user: %v", err)
	}

	m.logger.Info("MFA enabled", "user_id", userID)
	return secret, backupCodes, nil
}

// DisableMFA выключает двухфакторную аутентификацию
func (m *Manager) DisableMFA(userID, password string) error {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Проверка пароля
	if !m.verifyPassword(password, user.PasswordHash) {
		return fmt.Errorf("invalid password")
	}

	// Отключение MFA
	user.MFASecret = ""
	user.MFAEnabled = false
	user.BackupCodes = nil

	if err := m.db.SaveUser(user); err != nil {
		return fmt.Errorf("failed to save user: %v", err)
	}

	m.logger.Info("MFA disabled", "user_id", userID)
	return nil
}

// VerifyMFA проверяет код MFA
func (m *Manager) VerifyMFA(userID, code string) (bool, error) {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return false, fmt.Errorf("user not found")
	}

	if !user.MFAEnabled {
		return false, fmt.Errorf("MFA not enabled")
	}

	// Проверка кода
	if m.mfa.Verify(code, user.MFASecret) {
		return true, nil
	}

	// Проверка backup кодов
	if m.verifyBackupCode(code, user.BackupCodes) {
		// Удаление использованного кода
		m.removeBackupCode(code, user)
		return true, nil
	}

	return false, nil
}

// AddTrustedDevice добавляет доверенное устройство
func (m *Manager) AddTrustedDevice(userID, deviceID, deviceName, deviceType, fingerprint string) error {
	device := &TrustedDevice{
		ID:          generateDeviceID(),
		UserID:      userID,
		DeviceID:    deviceID,
		DeviceName:  deviceName,
		DeviceType:  deviceType,
		Fingerprint: fingerprint,
		LastUsed:    time.Now(),
		CreatedAt:   time.Now(),
		IsTrusted:   true,
	}

	user, err := m.db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	user.TrustedDevices = append(user.TrustedDevices, *device)
	
	if err := m.db.SaveUser(user); err != nil {
		return fmt.Errorf("failed to save user: %v", err)
	}

	m.logger.Info("Trusted device added", "user_id", userID, "device", deviceName)
	return nil
}

// RemoveTrustedDevice удаляет доверенное устройство
func (m *Manager) RemoveTrustedDevice(userID, deviceID string) error {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Удаление устройства
	for i, device := range user.TrustedDevices {
		if device.DeviceID == deviceID {
			user.TrustedDevices = append(user.TrustedDevices[:i], user.TrustedDevices[i+1:]...)
			break
		}
	}

	if err := m.db.SaveUser(user); err != nil {
		return fmt.Errorf("failed to save user: %v", err)
	}

	m.logger.Info("Trusted device removed", "user_id", userID, "device_id", deviceID)
	return nil
}

// IsDeviceTrusted проверяет, является ли устройство доверенным
func (m *Manager) IsDeviceTrusted(userID, fingerprint string) bool {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return false
	}

	for _, device := range user.TrustedDevices {
		if device.Fingerprint == fingerprint && device.IsTrusted {
			return true
		}
	}

	return false
}

// ChangePassword изменяет пароль пользователя
func (m *Manager) ChangePassword(userID, oldPassword, newPassword string) error {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Проверка старого пароля
	if !m.verifyPassword(oldPassword, user.PasswordHash) {
		return fmt.Errorf("invalid old password")
	}

	// Валидация нового пароля
	if err := m.validatePassword(newPassword); err != nil {
		return err
	}

	// Хеширование нового пароля
	newHash, err := m.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Обновление пользователя
	user.PasswordHash = newHash
	user.LastPasswordChange = time.Now()
	user.UpdatedAt = time.Now()

	if err := m.db.SaveUser(user); err != nil {
		return fmt.Errorf("failed to save user: %v", err)
	}

	// Инвалидация всех сессий (кроме текущей)
	m.invalidateSessions(userID)

	m.logger.Info("Password changed", "user_id", userID)
	return nil
}

// ResetPassword сбрасывает пароль
func (m *Manager) ResetPassword(email, token, newPassword string) error {
	// Проверка токена сброса
	if !m.validateResetToken(email, token) {
		return fmt.Errorf("invalid reset token")
	}

	user, err := m.db.GetUserByEmail(email)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	// Валидация нового пароля
	if err := m.validatePassword(newPassword); err != nil {
		return err
	}

	// Хеширование нового пароля
	newHash, err := m.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %v", err)
	}

	// Обновление пользователя
	user.PasswordHash = newHash
	user.LastPasswordChange = time.Now()
	user.UpdatedAt = time.Now()

	if err := m.db.SaveUser(user); err != nil {
		return fmt.Errorf("failed to save user: %v", err)
	}

	// Инвалидация всех сессий
	m.invalidateSessions(user.ID)

	// Удаление токена сброса
	m.deleteResetToken(email, token)

	m.logger.Info("Password reset", "email", email)
	return nil
}

// RequestPasswordReset запрашивает сброс пароля
func (m *Manager) RequestPasswordReset(email string) (string, error) {
	user, err := m.db.GetUserByEmail(email)
	if err != nil {
		// Не раскрываем, существует ли пользователь
		return "", nil
	}

	// Генерация токена сброса
	token := generateResetToken()
	expiresAt := time.Now().Add(1 * time.Hour)

	// Сохранение токена
	if err := m.db.SaveResetToken(email, token, expiresAt); err != nil {
		return "", fmt.Errorf("failed to save reset token: %v", err)
	}

	m.logger.Info("Password reset requested", "email", email)
	return token, nil
}

// SetSecurityQuestions устанавливает вопросы безопасности
func (m *Manager) SetSecurityQuestions(userID string, questions map[string]string) error {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	user.SecurityAnswers = questions
	user.UpdatedAt = time.Now()

	if err := m.db.SaveUser(user); err != nil {
		return fmt.Errorf("failed to save user: %v", err)
	}

	m.logger.Info("Security questions set", "user_id", userID)
	return nil
}

// VerifySecurityQuestions проверяет ответы на вопросы безопасности
func (m *Manager) VerifySecurityQuestions(userID string, answers map[string]string) (bool, error) {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return false, fmt.Errorf("user not found")
	}

	// Проверка ответов
	for question, answer := range answers {
		correctAnswer, exists := user.SecurityAnswers[question]
		if !exists {
			return false, nil
		}

		if !strings.EqualFold(strings.TrimSpace(answer), strings.TrimSpace(correctAnswer)) {
			return false, nil
		}
	}

	return true, nil
}

// GetUserPermissions возвращает разрешения пользователя
func (m *Manager) GetUserPermissions(userID string) ([]string, error) {
	user, err := m.db.GetUser(userID)
	if err != nil {
		return nil, fmt.Errorf("user not found")
	}

	// Базовые разрешения
	permissions := []string{"read"}

	// Разрешения на основе роли
	switch user.Role {
	case "admin":
		permissions = append(permissions, 
			"write", "delete", "manage_users", "manage_network", "view_logs")
	case "user":
		permissions = append(permissions, "write")
	case "guest":
		// Только чтение
	}

	// Добавление пользовательских разрешений
	permissions = append(permissions, user.Permissions...)

	return permissions, nil
}

// HasPermission проверяет наличие разрешения
func (m *Manager) HasPermission(userID, permission string) bool {
	permissions, err := m.GetUserPermissions(userID)
	if err != nil {
		return false
	}

	for _, p := range permissions {
		if p == permission {
			return true
		}
	}

	return false
}

// CleanupSessions очищает старые сессии
func (m *Manager) CleanupSessions() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for sessionID, session := range m.sessions {
		if session.ExpiresAt.Before(now) {
			delete(m.sessions, sessionID)
		}
	}

	// Очистка в БД
	m.db.CleanupSessions()
}

// Внутренние методы

func (m *Manager) createSession(userID, ipAddress, userAgent string) (*Session, error) {
	session := &Session{
		ID:           generateSessionID(),
		UserID:       userID,
		Token:        generateSessionToken(),
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		CreatedAt:    time.Now(),
		LastActivity: time.Now(),
		ExpiresAt:    time.Now().Add(24 * time.Hour), // 24 часа
		IsValid:      true,
		DeviceInfo: DeviceInfo{
			IP:        ipAddress,
			UserAgent: userAgent,
		},
	}

	// Сохранение в памяти
	m.sessions[session.ID] = session

	// Сохранение в БД
	if err := m.db.SaveSession(session); err != nil {
		delete(m.sessions, session.ID)
		return nil, fmt.Errorf("failed to save session: %v", err)
	}

	return session, nil
}

func (m *Manager) invalidateSessions(userID string) {
	// Инвалидация сессий в памяти
	for sessionID, session := range m.sessions {
		if session.UserID == userID {
			session.IsValid = false
			delete(m.sessions, sessionID)
		}
	}

	// Инвалидация сессий в БД
	m.db.InvalidateUserSessions(userID)
}

func (m *Manager) hashPassword(password string) (string, error) {
	// Генерация соли
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %v", err)
	}

	// Хеширование с использованием Argon2
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Комбинация соли и хеша
	result := make([]byte, len(salt)+len(hash))
	copy(result, salt)
	copy(result[len(salt):], hash)

	return base64.StdEncoding.EncodeToString(result), nil
}

func (m *Manager) verifyPassword(password, hashedPassword string) bool {
	// Декодирование хеша
	decoded, err := base64.StdEncoding.DecodeString(hashedPassword)
	if err != nil || len(decoded) < 16 {
		return false
	}

	// Извлечение соли и хеша
	salt := decoded[:16]
	storedHash := decoded[16:]

	// Вычисление хеша от предоставленного пароля
	computedHash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)

	// Сравнение хешей
	return subtle.ConstantTimeCompare(computedHash, storedHash) == 1
}

func (m *Manager) validatePassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Проверка сложности
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, ch := range password {
		switch {
		case 'A' <= ch && ch <= 'Z':
			hasUpper = true
		case 'a' <= ch && ch <= 'z':
			hasLower = true
		case '0' <= ch && ch <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+[]{}|;:,.<>?", ch):
			hasSpecial = true
		}
	}

	if !hasUpper || !hasLower || !hasDigit || !hasSpecial {
		return fmt.Errorf("password must contain uppercase, lowercase, digit and special character")
	}

	return nil
}

func (m *Manager) generateBackupCodes() []string {
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		code := make([]byte, 8)
		rand.Read(code)
		codes[i] = base32.StdEncoding.EncodeToString(code)[:8]
	}
	return codes
}

func (m *Manager) verifyBackupCode(code string, backupCodes []string) bool {
	for _, backupCode := range backupCodes {
		if strings.EqualFold(strings.TrimSpace(code), strings.TrimSpace(backupCode)) {
			return true
		}
	}
	return false
}

func (m *Manager) removeBackupCode(code string, user *User) {
	for i, backupCode := range user.BackupCodes {
		if strings.EqualFold(backupCode, code) {
			user.BackupCodes = append(user.BackupCodes[:i], user.BackupCodes[i+1:]...)
			m.db.SaveUser(user)
			break
		}
	}
}

func (m *Manager) validateResetToken(email, token string) bool {
	storedToken, expiresAt, err := m.db.GetResetToken(email)
	if err != nil {
		return false
	}

	if token != storedToken || time.Now().After(expiresAt) {
		return false
	}

	return true
}

func (m *Manager) deleteResetToken(email, token string) {
	m.db.DeleteResetToken(email, token)
}

// Вспомогательные функции

func generateUserID() string {
	return fmt.Sprintf("usr_%x", time.Now().UnixNano())
}

func generateSessionID() string {
	return fmt.Sprintf("sess_%x", time.Now().UnixNano())
}

func generateTokenID() string {
	return fmt.Sprintf("tok_%x", time.Now().UnixNano())
}

func generateDeviceID() string {
	return fmt.Sprintf("dev_%x", time.Now().UnixNano())
}

func generateSessionToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.URLEncoding.EncodeToString(token)
}

func generateSecureToken() string {
	token := make([]byte, 64)
	rand.Read(token)
	return base64.URLEncoding.EncodeToString(token)
}

func generateResetToken() string {
	token := make([]byte, 32)
	rand.Read(token)
	return base64.URLEncoding.EncodeToString(token)[:32]
}

// MFAManager управляет двухфакторной аутентификацией
type MFAManager struct{}

func NewMFAManager() *MFAManager {
	return &MFAManager{}
}

func (m *MFAManager) GenerateSecret(account string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Supressor",
		AccountName: account,
	})
	if err != nil {
		return "", err
	}
	return key.Secret(), nil
}

func (m *MFAManager) Verify(code, secret string) bool {
	return totp.Validate(code, secret)
}

func (m *MFAManager) GenerateQRCode(secret, account string) (string, error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Supressor",
		AccountName: account,
		Secret:      []byte(secret),
	})
	if err != nil {
		return "", err
	}

	// Генерация URL для QR кода
	url := key.URL()
	return url, nil
}

// RateLimiter ограничивает частоту запросов
type RateLimiter struct {
	attempts map[string]map[string][]time.Time
	mu       sync.RWMutex
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		attempts: make(map[string]map[string][]time.Time),
	}
}

func (r *RateLimiter) Allow(key, action string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Очистка старых попыток
	r.cleanup(key, action)

	// Проверка лимита
	attempts := r.getAttempts(key, action)
	if len(attempts) >= 5 { // 5 попыток
		return false
	}

	// Добавление новой попытки
	r.addAttempt(key, action)
	return true
}

func (r *RateLimiter) Increment(key, action string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.addAttempt(key, action)
}

func (r *RateLimiter) addAttempt(key, action string) {
	if r.attempts[key] == nil {
		r.attempts[key] = make(map[string][]time.Time)
	}
	r.attempts[key][action] = append(r.attempts[key][action], time.Now())
}

func (r *RateLimiter) getAttempts(key, action string) []time.Time {
	if r.attempts[key] == nil {
		return nil
	}
	return r.attempts[key][action]
}

func (r *RateLimiter) cleanup(key, action string) {
	attempts := r.getAttempts(key, action)
	now := time.Now()
	validAttempts := []time.Time{}

	for _, attempt := range attempts {
		if now.Sub(attempt) < 5*time.Minute { // 5 минутное окно
			validAttempts = append(validAttempts, attempt)
		}
	}

	if r.attempts[key] != nil {
		r.attempts[key][action] = validAttempts
	}
}
