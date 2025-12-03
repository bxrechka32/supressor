package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
	
	"supressor/internal/config"
	"supressor/internal/utils"
)

// Database представляет обертку над SQLite
type Database struct {
	db     *sql.DB
	path   string
	ctx    context.Context
	logger *utils.Logger
	mu     sync.RWMutex
}

// Models для таблиц

// UserModel представляет пользователя в БД
type UserModel struct {
	ID              string          `db:"id"`
	Username        string          `db:"username"`
	Email           string          `db:"email"`
	PasswordHash    string          `db:"password_hash"`
	DisplayName     string          `db:"display_name"`
	Avatar          string          `db:"avatar"`
	Role            string          `db:"role"`
	Permissions     string          `db:"permissions"` // JSON
	MFASecret       string          `db:"mfa_secret"`
	MFAEnabled      bool            `db:"mfa_enabled"`
	BackupCodes     string          `db:"backup_codes"` // JSON
	LastLogin       time.Time       `db:"last_login"`
	FailedAttempts  int             `db:"failed_attempts"`
	LockedUntil     time.Time       `db:"locked_until"`
	SecurityAnswers string          `db:"security_answers"` // JSON
	TrustedDevices  string          `db:"trusted_devices"`  // JSON
	CreatedAt       time.Time       `db:"created_at"`
	UpdatedAt       time.Time       `db:"updated_at"`
	IsActive        bool            `db:"is_active"`
}

// SessionModel представляет сессию в БД
type SessionModel struct {
	ID           string    `db:"id"`
	UserID       string    `db:"user_id"`
	Token        string    `db:"token"`
	IPAddress    string    `db:"ip_address"`
	UserAgent    string    `db:"user_agent"`
	DeviceInfo   string    `db:"device_info"` // JSON
	CreatedAt    time.Time `db:"created_at"`
	LastActivity time.Time `db:"last_activity"`
	ExpiresAt    time.Time `db:"expires_at"`
	IsValid      bool      `db:"is_valid"`
}

// NetworkModel представляет сеть в БД
type NetworkModel struct {
	ID          string    `db:"id"`
	Name        string    `db:"name"`
	Description string    `db:"description"`
	OwnerID     string    `db:"owner_id"`
	Config      string    `db:"config"` // JSON
	PasswordHash string   `db:"password_hash"`
	IsPublic    bool      `db:"is_public"`
	IsEncrypted bool      `db:"is_encrypted"`
	MemberCount int       `db:"member_count"`
	CreatedAt   time.Time `db:"created_at"`
	UpdatedAt   time.Time `db:"updated_at"`
	LastActive  time.Time `db:"last_active"`
}

// PeerModel представляет пира в БД
type PeerModel struct {
	ID              string    `db:"id"`
	NetworkID       string    `db:"network_id"`
	Name            string    `db:"name"`
	PublicKey       string    `db:"public_key"`
	AllowedIPs      string    `db:"allowed_ips"` // JSON
	Endpoint        string    `db:"endpoint"`
	DeviceInfo      string    `db:"device_info"` // JSON
	GeoLocation     string    `db:"geo_location"` // JSON
	TrustLevel      int       `db:"trust_level"`
	LastHandshake   time.Time `db:"last_handshake"`
	LastSeen        time.Time `db:"last_seen"`
	IsConnected     bool      `db:"is_connected"`
	IsBanned        bool      `db:"is_banned"`
	BanReason       string    `db:"ban_reason"`
	CreatedAt       time.Time `db:"created_at"`
	UpdatedAt       time.Time `db:"updated_at"`
}

// StatsModel представляет статистику в БД
type StatsModel struct {
	ID            string    `db:"id"`
	NetworkID     string    `db:"network_id"`
	PeerID        string    `db:"peer_id"`
	Timestamp     time.Time `db:"timestamp"`
	RxBytes       uint64    `db:"rx_bytes"`
	TxBytes       uint64    `db:"tx_bytes"`
	Latency       int       `db:"latency"` // ms
	Jitter        int       `db:"jitter"`  // ms
	PacketLoss    float64   `db:"packet_loss"`
	Connections   int       `db:"connections"`
	ProtocolStats string    `db:"protocol_stats"` // JSON
}

// SecurityEventModel представляет событие безопасности
type SecurityEventModel struct {
	ID        string    `db:"id"`
	Type      string    `db:"type"`
	Severity  string    `db:"severity"`
	Message   string    `db:"message"`
	PeerID    string    `db:"peer_id"`
	NetworkID string    `db:"network_id"`
	Data      string    `db:"data"` // JSON
	Timestamp time.Time `db:"timestamp"`
}

// Migration представляет миграцию БД
type Migration struct {
	ID        int       `db:"id"`
	Name      string    `db:"name"`
	SQL       string    `db:"sql"`
	AppliedAt time.Time `db:"applied_at"`
}

// New создает новую базу данных
func New(path string) (*Database, error) {
	if path == "" {
		// Путь по умолчанию
		configDir, _ := config.GetConfigDir()
		path = filepath.Join(configDir, "supressor.db")
	}

	logger := utils.NewLogger("database")

	db := &Database{
		path:   path,
		ctx:    context.Background(),
		logger: logger,
	}

	// Открытие/создание базы данных
	if err := db.open(); err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Применение миграций
	if err := db.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to migrate database: %v", err)
	}

	logger.Info("Database initialized", "path", path)
	return db, nil
}

// Init инициализирует базу данных
func (d *Database) Init() error {
	// Создание таблиц, если не существуют
	return d.createTables()
}

// Close закрывает соединение с БД
func (d *Database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.db != nil {
		return d.db.Close()
	}
	return nil
}

// HealthCheck проверяет состояние БД
func (d *Database) HealthCheck() error {
	d.mu.RLock()
	defer d.mu.RUnlock()

	// Простой ping запрос
	return d.db.PingContext(d.ctx)
}

// Backup создает резервную копию БД
func (d *Database) Backup(backupPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// SQLite команда для резервного копирования
	backupSQL := fmt.Sprintf("VACUUM INTO '%s'", backupPath)
	_, err := d.db.ExecContext(d.ctx, backupSQL)
	return err
}

// Restore восстанавливает БД из резервной копии
func (d *Database) Restore(backupPath string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Закрываем текущее соединение
	d.db.Close()

	// Копируем файл резервной копии
	if err := copyFile(backupPath, d.path); err != nil {
		return fmt.Errorf("failed to restore backup: %v", err)
	}

	// Открываем восстановленную БД
	return d.open()
}

// User methods

// SaveUser сохраняет пользователя
func (d *Database) SaveUser(user *config.User) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Конвертация в модель
	model := d.userToModel(user)

	query := `
	INSERT OR REPLACE INTO users (
		id, username, email, password_hash, display_name, avatar, role,
		permissions, mfa_secret, mfa_enabled, backup_codes, last_login,
		failed_attempts, locked_until, security_answers, trusted_devices,
		created_at, updated_at, is_active
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.ExecContext(d.ctx, query,
		model.ID, model.Username, model.Email, model.PasswordHash,
		model.DisplayName, model.Avatar, model.Role, model.Permissions,
		model.MFASecret, model.MFAEnabled, model.BackupCodes, model.LastLogin,
		model.FailedAttempts, model.LockedUntil, model.SecurityAnswers,
		model.TrustedDevices, model.CreatedAt, model.UpdatedAt, model.IsActive,
	)

	return err
}

// GetUser получает пользователя по ID
func (d *Database) GetUser(id string) (*config.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM users WHERE id = ?`
	row := d.db.QueryRowContext(d.ctx, query, id)

	var model UserModel
	if err := row.Scan(&model.ID, &model.Username, &model.Email,
		&model.PasswordHash, &model.DisplayName, &model.Avatar, &model.Role,
		&model.Permissions, &model.MFASecret, &model.MFAEnabled,
		&model.BackupCodes, &model.LastLogin, &model.FailedAttempts,
		&model.LockedUntil, &model.SecurityAnswers, &model.TrustedDevices,
		&model.CreatedAt, &model.UpdatedAt, &model.IsActive); err != nil {
		return nil, err
	}

	return d.modelToUser(&model)
}

// GetUserByUsername получает пользователя по имени
func (d *Database) GetUserByUsername(username string) (*config.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM users WHERE username = ?`
	row := d.db.QueryRowContext(d.ctx, query, username)

	var model UserModel
	if err := row.Scan(&model.ID, &model.Username, &model.Email,
		&model.PasswordHash, &model.DisplayName, &model.Avatar, &model.Role,
		&model.Permissions, &model.MFASecret, &model.MFAEnabled,
		&model.BackupCodes, &model.LastLogin, &model.FailedAttempts,
		&model.LockedUntil, &model.SecurityAnswers, &model.TrustedDevices,
		&model.CreatedAt, &model.UpdatedAt, &model.IsActive); err != nil {
		return nil, err
	}

	return d.modelToUser(&model)
}

// GetUserByEmail получает пользователя по email
func (d *Database) GetUserByEmail(email string) (*config.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM users WHERE email = ?`
	row := d.db.QueryRowContext(d.ctx, query, email)

	var model UserModel
	if err := row.Scan(&model.ID, &model.Username, &model.Email,
		&model.PasswordHash, &model.DisplayName, &model.Avatar, &model.Role,
		&model.Permissions, &model.MFASecret, &model.MFAEnabled,
		&model.BackupCodes, &model.LastLogin, &model.FailedAttempts,
		&model.LockedUntil, &model.SecurityAnswers, &model.TrustedDevices,
		&model.CreatedAt, &model.UpdatedAt, &model.IsActive); err != nil {
		return nil, err
	}

	return d.modelToUser(&model)
}

// UserExists проверяет существование пользователя
func (d *Database) UserExists(username, email string) (bool, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT COUNT(*) FROM users WHERE username = ? OR email = ?`
	var count int
	err := d.db.QueryRowContext(d.ctx, query, username, email).Scan(&count)
	return count > 0, err
}

// DeleteUser удаляет пользователя
func (d *Database) DeleteUser(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `DELETE FROM users WHERE id = ?`
	_, err := d.db.ExecContext(d.ctx, query, id)
	return err
}

// ListUsers возвращает список пользователей
func (d *Database) ListUsers(limit, offset int) ([]*config.User, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`
	rows, err := d.db.QueryContext(d.ctx, query, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*config.User
	for rows.Next() {
		var model UserModel
		if err := rows.Scan(&model.ID, &model.Username, &model.Email,
			&model.PasswordHash, &model.DisplayName, &model.Avatar, &model.Role,
			&model.Permissions, &model.MFASecret, &model.MFAEnabled,
			&model.BackupCodes, &model.LastLogin, &model.FailedAttempts,
			&model.LockedUntil, &model.SecurityAnswers, &model.TrustedDevices,
			&model.CreatedAt, &model.UpdatedAt, &model.IsActive); err != nil {
			return nil, err
		}

		user, err := d.modelToUser(&model)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}

	return users, nil
}

// Session methods

// SaveSession сохраняет сессию
func (d *Database) SaveSession(session *config.Session) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	deviceInfo, _ := json.Marshal(session.DeviceInfo)

	query := `
	INSERT OR REPLACE INTO sessions (
		id, user_id, token, ip_address, user_agent, device_info,
		created_at, last_activity, expires_at, is_valid
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.ExecContext(d.ctx, query,
		session.ID, session.UserID, session.Token, session.IPAddress,
		session.UserAgent, deviceInfo, session.CreatedAt,
		session.LastActivity, session.ExpiresAt, session.IsValid,
	)

	return err
}

// GetSession получает сессию по ID
func (d *Database) GetSession(id string) (*config.Session, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM sessions WHERE id = ?`
	row := d.db.QueryRowContext(d.ctx, query, id)

	var model SessionModel
	var deviceInfo []byte
	if err := row.Scan(&model.ID, &model.UserID, &model.Token,
		&model.IPAddress, &model.UserAgent, &deviceInfo, &model.CreatedAt,
		&model.LastActivity, &model.ExpiresAt, &model.IsValid); err != nil {
		return nil, err
	}

	var device config.DeviceInfo
	if len(deviceInfo) > 0 {
		json.Unmarshal(deviceInfo, &device)
	}

	return &config.Session{
		ID:           model.ID,
		UserID:       model.UserID,
		Token:        model.Token,
		IPAddress:    model.IPAddress,
		UserAgent:    model.UserAgent,
		DeviceInfo:   device,
		CreatedAt:    model.CreatedAt,
		LastActivity: model.LastActivity,
		ExpiresAt:    model.ExpiresAt,
		IsValid:      model.IsValid,
	}, nil
}

// GetSessionByToken получает сессию по токену
func (d *Database) GetSessionByToken(token string) (*config.Session, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM sessions WHERE token = ?`
	row := d.db.QueryRowContext(d.ctx, query, token)

	var model SessionModel
	var deviceInfo []byte
	if err := row.Scan(&model.ID, &model.UserID, &model.Token,
		&model.IPAddress, &model.UserAgent, &deviceInfo, &model.CreatedAt,
		&model.LastActivity, &model.ExpiresAt, &model.IsValid); err != nil {
		return nil, err
	}

	var device config.DeviceInfo
	if len(deviceInfo) > 0 {
		json.Unmarshal(deviceInfo, &device)
	}

	return &config.Session{
		ID:           model.ID,
		UserID:       model.UserID,
		Token:        model.Token,
		IPAddress:    model.IPAddress,
		UserAgent:    model.UserAgent,
		DeviceInfo:   device,
		CreatedAt:    model.CreatedAt,
		LastActivity: model.LastActivity,
		ExpiresAt:    model.ExpiresAt,
		IsValid:      model.IsValid,
	}, nil
}

// InvalidateUserSessions инвалидирует все сессии пользователя
func (d *Database) InvalidateUserSessions(userID string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `UPDATE sessions SET is_valid = 0 WHERE user_id = ?`
	_, err := d.db.ExecContext(d.ctx, query, userID)
	return err
}

// CleanupSessions очищает старые сессии
func (d *Database) CleanupSessions() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `DELETE FROM sessions WHERE expires_at < ? OR is_valid = 0`
	_, err := d.db.ExecContext(d.ctx, query, time.Now())
	return err
}

// Network methods

// SaveNetwork сохраняет сеть
func (d *Database) SaveNetwork(id string, networkConfig *config.NetworkConfig, password string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	configJSON, _ := json.Marshal(networkConfig)
	passwordHash := hashPassword(password)

	query := `
	INSERT INTO networks (
		id, name, description, owner_id, config, password_hash,
		is_public, is_encrypted, member_count, created_at, updated_at, last_active
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.ExecContext(d.ctx, query,
		id, networkConfig.Name, networkConfig.Description,
		"system", configJSON, passwordHash, false, password != "",
		1, time.Now(), time.Now(), time.Now(),
	)

	return err
}

// LoadNetwork загружает сеть
func (d *Database) LoadNetwork(id, password string) (*config.NetworkConfig, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT config, password_hash, is_encrypted FROM networks WHERE id = ?`
	row := d.db.QueryRowContext(d.ctx, query, id)

	var configJSON, passwordHash []byte
	var isEncrypted bool
	if err := row.Scan(&configJSON, &passwordHash, &isEncrypted); err != nil {
		return nil, err
	}

	// Проверка пароля если сеть зашифрована
	if isEncrypted && !verifyPassword(password, string(passwordHash)) {
		return nil, fmt.Errorf("invalid password")
	}

	var networkConfig config.NetworkConfig
	if err := json.Unmarshal(configJSON, &networkConfig); err != nil {
		return nil, err
	}

	return &networkConfig, nil
}

// UpdateNetwork обновляет сеть
func (d *Database) UpdateNetwork(id string, updater func(*NetworkModel)) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Получаем текущую сеть
	query := `SELECT * FROM networks WHERE id = ?`
	row := d.db.QueryRowContext(d.ctx, query, id)

	var model NetworkModel
	if err := row.Scan(&model.ID, &model.Name, &model.Description,
		&model.OwnerID, &model.Config, &model.PasswordHash, &model.IsPublic,
		&model.IsEncrypted, &model.MemberCount, &model.CreatedAt,
		&model.UpdatedAt, &model.LastActive); err != nil {
		return err
	}

	// Обновляем
	updater(&model)
	model.UpdatedAt = time.Now()

	// Сохраняем
	updateQuery := `
	UPDATE networks SET
		name = ?, description = ?, owner_id = ?, config = ?, password_hash = ?,
		is_public = ?, is_encrypted = ?, member_count = ?, updated_at = ?, last_active = ?
	WHERE id = ?
	`

	_, err := d.db.ExecContext(d.ctx, updateQuery,
		model.Name, model.Description, model.OwnerID, model.Config,
		model.PasswordHash, model.IsPublic, model.IsEncrypted,
		model.MemberCount, model.UpdatedAt, model.LastActive, model.ID,
	)

	return err
}

// DeleteNetwork удаляет сеть
func (d *Database) DeleteNetwork(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Удаляем связанные данные
	queries := []string{
		`DELETE FROM peers WHERE network_id = ?`,
		`DELETE FROM stats WHERE network_id = ?`,
		`DELETE FROM security_events WHERE network_id = ?`,
		`DELETE FROM networks WHERE id = ?`,
	}

	for _, query := range queries {
		if _, err := d.db.ExecContext(d.ctx, query, id); err != nil {
			return err
		}
	}

	return nil
}

// ListNetworks возвращает список сетей
func (d *Database) ListNetworks(userID string, limit, offset int) ([]*NetworkModel, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `
	SELECT * FROM networks 
	WHERE is_public = 1 OR owner_id = ?
	ORDER BY last_active DESC 
	LIMIT ? OFFSET ?
	`
	rows, err := d.db.QueryContext(d.ctx, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var networks []*NetworkModel
	for rows.Next() {
		var model NetworkModel
		if err := rows.Scan(&model.ID, &model.Name, &model.Description,
			&model.OwnerID, &model.Config, &model.PasswordHash, &model.IsPublic,
			&model.IsEncrypted, &model.MemberCount, &model.CreatedAt,
			&model.UpdatedAt, &model.LastActive); err != nil {
			return nil, err
		}
		networks = append(networks, &model)
	}

	return networks, nil
}

// Peer methods

// SavePeer сохраняет пира
func (d *Database) SavePeer(peer *config.Peer) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	allowedIPs, _ := json.Marshal(peer.AllowedIPs)
	deviceInfo, _ := json.Marshal(peer.DeviceInfo)
	geoLocation, _ := json.Marshal(peer.GeoLocation)

	endpoint := ""
	if peer.Endpoint != nil {
		endpoint = peer.Endpoint.String()
	}

	query := `
	INSERT OR REPLACE INTO peers (
		id, network_id, name, public_key, allowed_ips, endpoint,
		device_info, geo_location, trust_level, last_handshake,
		last_seen, is_connected, is_banned, ban_reason,
		created_at, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.ExecContext(d.ctx, query,
		peer.ID, peer.NetworkID, peer.Name, peer.PublicKey, allowedIPs,
		endpoint, deviceInfo, geoLocation, int(peer.TrustLevel),
		peer.LastHandshake, peer.LastSeen, peer.IsConnected,
		peer.IsBanned, peer.BanReason, peer.CreatedAt, peer.UpdatedAt,
	)

	return err
}

// GetPeer получает пира по ID
func (d *Database) GetPeer(id string) (*config.Peer, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM peers WHERE id = ?`
	row := d.db.QueryRowContext(d.ctx, query, id)

	var model PeerModel
	var allowedIPs, deviceInfo, geoLocation []byte
	var endpoint string

	if err := row.Scan(&model.ID, &model.NetworkID, &model.Name,
		&model.PublicKey, &allowedIPs, &endpoint, &deviceInfo,
		&geoLocation, &model.TrustLevel, &model.LastHandshake,
		&model.LastSeen, &model.IsConnected, &model.IsBanned,
		&model.BanReason, &model.CreatedAt, &model.UpdatedAt); err != nil {
		return nil, err
	}

	// Парсинг JSON полей
	var ips []net.IPNet
	json.Unmarshal(allowedIPs, &ips)

	var device config.DeviceInfo
	json.Unmarshal(deviceInfo, &device)

	var geo config.GeoLocation
	json.Unmarshal(geoLocation, &geo)

	var addr *net.UDPAddr
	if endpoint != "" {
		addr, _ = net.ResolveUDPAddr("udp", endpoint)
	}

	return &config.Peer{
		ID:            model.ID,
		NetworkID:     model.NetworkID,
		Name:          model.Name,
		PublicKey:     model.PublicKey,
		AllowedIPs:    ips,
		Endpoint:      addr,
		DeviceInfo:    &device,
		GeoLocation:   &geo,
		TrustLevel:    config.TrustLevel(model.TrustLevel),
		LastHandshake: model.LastHandshake,
		LastSeen:      model.LastSeen,
		IsConnected:   model.IsConnected,
		IsBanned:      model.IsBanned,
		BanReason:     model.BanReason,
		CreatedAt:     model.CreatedAt,
		UpdatedAt:     model.UpdatedAt,
	}, nil
}

// DeletePeer удаляет пира
func (d *Database) DeletePeer(id string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `DELETE FROM peers WHERE id = ?`
	_, err := d.db.ExecContext(d.ctx, query, id)
	return err
}

// ListPeers возвращает список пиров в сети
func (d *Database) ListPeers(networkID string) ([]*config.Peer, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `SELECT * FROM peers WHERE network_id = ? ORDER BY last_seen DESC`
	rows, err := d.db.QueryContext(d.ctx, query, networkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var peers []*config.Peer
	for rows.Next() {
		var model PeerModel
		var allowedIPs, deviceInfo, geoLocation []byte
		var endpoint string

		if err := rows.Scan(&model.ID, &model.NetworkID, &model.Name,
			&model.PublicKey, &allowedIPs, &endpoint, &deviceInfo,
			&geoLocation, &model.TrustLevel, &model.LastHandshake,
			&model.LastSeen, &model.IsConnected, &model.IsBanned,
			&model.BanReason, &model.CreatedAt, &model.UpdatedAt); err != nil {
			return nil, err
		}

		// Парсинг JSON полей
		var ips []net.IPNet
		json.Unmarshal(allowedIPs, &ips)

		var device config.DeviceInfo
		json.Unmarshal(deviceInfo, &device)

		var geo config.GeoLocation
		json.Unmarshal(geoLocation, &geo)

		var addr *net.UDPAddr
		if endpoint != "" {
			addr, _ = net.ResolveUDPAddr("udp", endpoint)
		}

		peer := &config.Peer{
			ID:            model.ID,
			NetworkID:     model.NetworkID,
			Name:          model.Name,
			PublicKey:     model.PublicKey,
			AllowedIPs:    ips,
			Endpoint:      addr,
			DeviceInfo:    &device,
			GeoLocation:   &geo,
			TrustLevel:    config.TrustLevel(model.TrustLevel),
			LastHandshake: model.LastHandshake,
			LastSeen:      model.LastSeen,
			IsConnected:   model.IsConnected,
			IsBanned:      model.IsBanned,
			BanReason:     model.BanReason,
			CreatedAt:     model.CreatedAt,
			UpdatedAt:     model.UpdatedAt,
		}

		peers = append(peers, peer)
	}

	return peers, nil
}

// BanPeer блокирует пира
func (d *Database) BanPeer(peerID, publicKey, reason string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	query := `
	UPDATE peers SET 
		is_banned = 1, ban_reason = ?, updated_at = ?
	WHERE id = ? OR public_key = ?
	`

	_, err := d.db.ExecContext(d.ctx, query,
		reason, time.Now(), peerID, publicKey,
	)

	return err
}

// Stats methods

// SaveStats сохраняет статистику
func (d *Database) SaveStats(stats *config.Stats) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	protocolStats, _ := json.Marshal(stats.ProtocolStats)

	query := `
	INSERT INTO stats (
		id, network_id, peer_id, timestamp, rx_bytes, tx_bytes,
		latency, jitter, packet_loss, connections, protocol_stats
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.ExecContext(d.ctx, query,
		generateID(), stats.NetworkID, stats.PeerID, stats.Timestamp,
		stats.RxBytes, stats.TxBytes, int(stats.Latency.Milliseconds()),
		int(stats.Jitter.Milliseconds()), stats.PacketLoss,
		stats.Connections, protocolStats,
	)

	return err
}

// GetStats возвращает статистику за период
func (d *Database) GetStats(networkID, peerID string, from, to time.Time) ([]*config.Stats, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `
	SELECT * FROM stats 
	WHERE network_id = ? AND peer_id = ? AND timestamp BETWEEN ? AND ?
	ORDER BY timestamp
	`
	rows, err := d.db.QueryContext(d.ctx, query, networkID, peerID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var statsList []*config.Stats
	for rows.Next() {
		var model StatsModel
		var protocolStats []byte

		if err := rows.Scan(&model.ID, &model.NetworkID, &model.PeerID,
			&model.Timestamp, &model.RxBytes, &model.TxBytes, &model.Latency,
			&model.Jitter, &model.PacketLoss, &model.Connections,
			&protocolStats); err != nil {
			return nil, err
		}

		var protoStats map[string]uint64
		json.Unmarshal(protocolStats, &protoStats)

		stats := &config.Stats{
			NetworkID:     model.NetworkID,
			PeerID:        model.PeerID,
			Timestamp:     model.Timestamp,
			RxBytes:       model.RxBytes,
			TxBytes:       model.TxBytes,
			Latency:       time.Duration(model.Latency) * time.Millisecond,
			Jitter:        time.Duration(model.Jitter) * time.Millisecond,
			PacketLoss:    model.PacketLoss,
			Connections:   model.Connections,
			ProtocolStats: protoStats,
		}

		statsList = append(statsList, stats)
	}

	return statsList, nil
}

// SecurityEvent methods

// SaveSecurityEvent сохраняет событие безопасности
func (d *Database) SaveSecurityEvent(event *config.SecurityEvent) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	data, _ := json.Marshal(event.Data)

	query := `
	INSERT INTO security_events (
		id, type, severity, message, peer_id, network_id, data, timestamp
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := d.db.ExecContext(d.ctx, query,
		generateID(), event.Type, event.Severity, event.Message,
		event.PeerID, event.NetworkID, data, event.Timestamp,
	)

	return err
}

// GetSecurityEvents возвращает события безопасности
func (d *Database) GetSecurityEvents(networkID string, limit int) ([]*config.SecurityEvent, error) {
	d.mu.RLock()
	defer d.mu.RUnlock()

	query := `
	SELECT * FROM security_events 
	WHERE network_id = ? 
	ORDER BY timestamp DESC 
	LIMIT ?
	`
	rows, err := d.db.QueryContext(d.ctx, query, networkID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*config.SecurityEvent
	for rows.Next() {
		var model SecurityEventModel
		var data []byte

		if err := rows.Scan(&model.ID, &model.Type, &model.Severity,
			&model.Message, &model.PeerID, &model.NetworkID, &data,
			&model.Timestamp); err != nil {
			return nil, err
		}

		var eventData json.RawMessage
		json.Unmarshal(data, &eventData)

		event := &config.SecurityEvent{
			ID:        model.ID,
			Type:      model.Type,
			Severity:  model.Severity,
			Message:   model.Message,
			PeerID:    model.PeerID,
			NetworkID: model.NetworkID,
			Data:      eventData,
			Timestamp: model.Timestamp,
		}

		events = append(events, event)
	}

	return events, nil
}

// Внутренние методы

func (d *Database) open() error {
	// Создание директории если не существует
	dir := filepath.Dir(d.path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Открытие базы данных
	db, err := sql.Open("sqlite", d.path+"?_journal=WAL&_timeout=5000")
	if err != nil {
		return err
	}

	// Настройка пула соединений
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Проверка соединения
	if err := db.Ping(); err != nil {
		db.Close()
		return err
	}

	d.db = db
	return nil
}

func (d *Database) createTables() error {
	tables := []string{
		// Таблица пользователей
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			username TEXT UNIQUE NOT NULL,
			email TEXT UNIQUE NOT NULL,
			password_hash TEXT NOT NULL,
			display_name TEXT,
			avatar TEXT,
			role TEXT NOT NULL DEFAULT 'user',
			permissions TEXT DEFAULT '[]',
			mfa_secret TEXT,
			mfa_enabled BOOLEAN DEFAULT 0,
			backup_codes TEXT DEFAULT '[]',
			last_login TIMESTAMP,
			failed_attempts INTEGER DEFAULT 0,
			locked_until TIMESTAMP,
			security_answers TEXT DEFAULT '{}',
			trusted_devices TEXT DEFAULT '[]',
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			is_active BOOLEAN DEFAULT 1
		)`,

		// Таблица сессий
		`CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token TEXT UNIQUE NOT NULL,
			ip_address TEXT NOT NULL,
			user_agent TEXT,
			device_info TEXT,
			created_at TIMESTAMP NOT NULL,
			last_activity TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			is_valid BOOLEAN DEFAULT 1,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Таблица сетей
		`CREATE TABLE IF NOT EXISTS networks (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			description TEXT,
			owner_id TEXT NOT NULL,
			config TEXT NOT NULL,
			password_hash TEXT,
			is_public BOOLEAN DEFAULT 0,
			is_encrypted BOOLEAN DEFAULT 0,
			member_count INTEGER DEFAULT 0,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			last_active TIMESTAMP NOT NULL
		)`,

		// Таблица пиров
		`CREATE TABLE IF NOT EXISTS peers (
			id TEXT PRIMARY KEY,
			network_id TEXT NOT NULL,
			name TEXT NOT NULL,
			public_key TEXT UNIQUE NOT NULL,
			allowed_ips TEXT DEFAULT '[]',
			endpoint TEXT,
			device_info TEXT,
			geo_location TEXT,
			trust_level INTEGER DEFAULT 0,
			last_handshake TIMESTAMP,
			last_seen TIMESTAMP NOT NULL,
			is_connected BOOLEAN DEFAULT 0,
			is_banned BOOLEAN DEFAULT 0,
			ban_reason TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE
		)`,

		// Таблица статистики
		`CREATE TABLE IF NOT EXISTS stats (
			id TEXT PRIMARY KEY,
			network_id TEXT NOT NULL,
			peer_id TEXT,
			timestamp TIMESTAMP NOT NULL,
			rx_bytes INTEGER DEFAULT 0,
			tx_bytes INTEGER DEFAULT 0,
			latency INTEGER, -- ms
			jitter INTEGER,  -- ms
			packet_loss REAL,
			connections INTEGER DEFAULT 0,
			protocol_stats TEXT DEFAULT '{}',
			FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE,
			FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE SET NULL
		)`,

		// Таблица событий безопасности
		`CREATE TABLE IF NOT EXISTS security_events (
			id TEXT PRIMARY KEY,
			type TEXT NOT NULL,
			severity TEXT NOT NULL,
			message TEXT NOT NULL,
			peer_id TEXT,
			network_id TEXT NOT NULL,
			data TEXT,
			timestamp TIMESTAMP NOT NULL,
			FOREIGN KEY (network_id) REFERENCES networks(id) ON DELETE CASCADE,
			FOREIGN KEY (peer_id) REFERENCES peers(id) ON DELETE SET NULL
		)`,

		// Таблица токенов
		`CREATE TABLE IF NOT EXISTS tokens (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token TEXT UNIQUE NOT NULL,
			type TEXT NOT NULL,
			scope TEXT DEFAULT '[]',
			created_at TIMESTAMP NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			is_revoked BOOLEAN DEFAULT 0,
			FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
		)`,

		// Таблица токенов сброса пароля
		`CREATE TABLE IF NOT EXISTS reset_tokens (
			email TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP NOT NULL
		)`,

		// Таблица миграций
		`CREATE TABLE IF NOT EXISTS migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL,
			sql TEXT NOT NULL,
			applied_at TIMESTAMP NOT NULL
		)`,

		// Индексы для производительности
		`CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)`,
		`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token)`,
		`CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS idx_peers_network_id ON peers(network_id)`,
		`CREATE INDEX IF NOT EXISTS idx_peers_public_key ON peers(public_key)`,
		`CREATE INDEX IF NOT EXISTS idx_stats_network_id ON stats(network_id)`,
		`CREATE INDEX IF NOT EXISTS idx_stats_timestamp ON stats(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_network_id ON security_events(network_id)`,
		`CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_token ON tokens(token)`,
		`CREATE INDEX IF NOT EXISTS idx_tokens_user_id ON tokens(user_id)`,
	}

	for _, tableSQL := range tables {
		if _, err := d.db.ExecContext(d.ctx, tableSQL); err != nil {
			return fmt.Errorf("failed to create table: %v\nSQL: %s", err, tableSQL)
		}
	}

	d.logger.Info("Database tables created/verified")
	return nil
}

func (d *Database) migrate() error {
	// Получение текущей версии миграции
	var currentVersion int
	query := `SELECT COALESCE(MAX(id), 0) FROM migrations`
	d.db.QueryRowContext(d.ctx, query).Scan(&currentVersion)

	// Список миграций
	migrations := []Migration{
		{
			ID:   1,
			Name: "initial_schema",
			SQL:  initialSchemaSQL,
		},
		{
			ID:   2,
			Name: "add_network_stats",
			SQL:  addNetworkStatsSQL,
		},
		{
			ID:   3,
			Name: "add_security_events",
			SQL:  addSecurityEventsSQL,
		},
		// Добавьте дополнительные миграции здесь
	}

	// Применение недостающих миграций
	for _, migration := range migrations {
		if migration.ID > currentVersion {
			d.logger.Info("Applying migration", "id", migration.ID, "name", migration.Name)
			
			// Начало транзакции
			tx, err := d.db.BeginTx(d.ctx, nil)
			if err != nil {
				return err
			}

			// Применение миграции
			if _, err := tx.ExecContext(d.ctx, migration.SQL); err != nil {
				tx.Rollback()
				return fmt.Errorf("failed to apply migration %d: %v", migration.ID, err)
			}

			// Запись миграции в таблицу
			insertSQL := `INSERT INTO migrations (id, name, sql, applied_at) VALUES (?, ?, ?, ?)`
			if _, err := tx.ExecContext(d.ctx, insertSQL,
				migration.ID, migration.Name, migration.SQL, time.Now()); err != nil {
				tx.Rollback()
				return err
			}

			// Коммит транзакции
			if err := tx.Commit(); err != nil {
				return err
			}

			d.logger.Info("Migration applied", "id", migration.ID)
		}
	}

	return nil
}

func (d *Database) userToModel(user *config.User) *UserModel {
	permissions, _ := json.Marshal(user.Permissions)
	backupCodes, _ := json.Marshal(user.BackupCodes)
	securityAnswers, _ := json.Marshal(user.SecurityAnswers)
	trustedDevices, _ := json.Marshal(user.TrustedDevices)

	return &UserModel{
		ID:              user.ID,
		Username:        user.Username,
		Email:           user.Email,
		PasswordHash:    user.PasswordHash,
		DisplayName:     user.DisplayName,
		Avatar:          user.Avatar,
		Role:            user.Role,
		Permissions:     string(permissions),
		MFASecret:       user.MFASecret,
		MFAEnabled:      user.MFAEnabled,
		BackupCodes:     string(backupCodes),
		LastLogin:       user.LastLogin,
		FailedAttempts:  user.FailedAttempts,
		LockedUntil:     user.LockedUntil,
		SecurityAnswers: string(securityAnswers),
		TrustedDevices:  string(trustedDevices),
		CreatedAt:       user.CreatedAt,
		UpdatedAt:       user.UpdatedAt,
		IsActive:        user.IsActive,
	}
}

func (d *Database) modelToUser(model *UserModel) (*config.User, error) {
	var permissions []string
	var backupCodes []string
	var securityAnswers map[string]string
	var trustedDevices []config.TrustedDevice

	json.Unmarshal([]byte(model.Permissions), &permissions)
	json.Unmarshal([]byte(model.BackupCodes), &backupCodes)
	json.Unmarshal([]byte(model.SecurityAnswers), &securityAnswers)
	json.Unmarshal([]byte(model.TrustedDevices), &trustedDevices)

	return &config.User{
		ID:              model.ID,
		Username:        model.Username,
		Email:           model.Email,
		PasswordHash:    model.PasswordHash,
		DisplayName:     model.DisplayName,
		Avatar:          model.Avatar,
		Role:            model.Role,
		Permissions:     permissions,
		MFASecret:       model.MFASecret,
		MFAEnabled:      model.MFAEnabled,
		BackupCodes:     backupCodes,
		LastLogin:       model.LastLogin,
		FailedAttempts:  model.FailedAttempts,
		LockedUntil:     model.LockedUntil,
		SecurityAnswers: securityAnswers,
		TrustedDevices:  trustedDevices,
		CreatedAt:       model.CreatedAt,
		UpdatedAt:       model.UpdatedAt,
		IsActive:        model.IsActive,
	}, nil
}

// Вспомогательные функции

func generateID() string {
	return fmt.Sprintf("id_%x", time.Now().UnixNano())
}

func hashPassword(password string) string {
	if password == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(password))
	return base64.StdEncoding.EncodeToString(hash[:])
}

func verifyPassword(password, hash string) bool {
	if password == "" || hash == "" {
		return false
	}
	computedHash := sha256.Sum256([]byte(password))
	computedHashStr := base64.StdEncoding.EncodeToString(computedHash[:])
	return computedHashStr == hash
}

func copyFile(src, dst string) error {
	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, input, 0644)
}

// SQL для миграций

const initialSchemaSQL = `
-- Эта миграция уже применена через createTables()
`

const addNetworkStatsSQL = `
-- Дополнительные индексы и таблицы для статистики
CREATE INDEX IF NOT EXISTS idx_stats_peer_timestamp ON stats(peer_id, timestamp);
CREATE INDEX IF NOT EXISTS idx_stats_network_timestamp ON stats(network_id, timestamp);
`

const addSecurityEventsSQL = `
-- Дополнительные индексы для событий безопасности
CREATE INDEX IF NOT EXISTS idx_security_events_peer_id ON security_events(peer_id);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
`
