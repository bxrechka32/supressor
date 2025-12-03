package config

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"supressor/internal/utils"
)

// Config представляет основную конфигурацию приложения
type Config struct {
	// Основные настройки
	AppName     string `toml:"app_name" json:"app_name"`
	Version     string `toml:"version" json:"version"`
	Environment string `toml:"environment" json:"environment"`

	// Настройки сети
	Network struct {
		Interface      string   `toml:"interface" json:"interface"`
		Port           int      `toml:"port" json:"port"`
		MTU            int      `toml:"mtu" json:"mtu"`
		DNS            []string `toml:"dns" json:"dns"`
		AllowedIPs     []string `toml:"allowed_ips" json:"allowed_ips"`
		PersistentKeepalive int `toml:"persistent_keepalive" json:"persistent_keepalive"`
		Table          string   `toml:"table" json:"table"`
		PreUp          []string `toml:"pre_up" json:"pre_up"`
		PostUp         []string `toml:"post_up" json:"post_up"`
		PreDown        []string `toml:"pre_down" json:"pre_down"`
		PostDown       []string `toml:"post_down" json:"post_down"`
	} `toml:"network" json:"network"`

	// Настройки безопасности
	Security struct {
		EncryptionAlgorithm string `toml:"encryption_algorithm" json:"encryption_algorithm"`
		KeyRotationInterval string `toml:"key_rotation_interval" json:"key_rotation_interval"`
		SessionTimeout      string `toml:"session_timeout" json:"session_timeout"`
		MaxLoginAttempts    int    `toml:"max_login_attempts" json:"max_login_attempts"`
		Require2FA         bool   `toml:"require_2fa" json:"require_2fa"`
		AllowedCountries   []string `toml:"allowed_countries" json:"allowed_countries"`
		BlockedIPs         []string `toml:"blocked_ips" json:"blocked_ips"`
	} `toml:"security" json:"security"`

	// Настройки базы данных
	Database struct {
		Path     string `toml:"path" json:"path"`
		Encrypted bool  `toml:"encrypted" json:"encrypted"`
		Backup struct {
			Enabled  bool   `toml:"enabled" json:"enabled"`
			Interval string `toml:"interval" json:"interval"`
			KeepDays int    `toml:"keep_days" json:"keep_days"`
		} `toml:"backup" json:"backup"`
	} `toml:"database" json:"database"`

	// Настройки API
	API struct {
		Enabled  bool   `toml:"enabled" json:"enabled"`
		Host     string `toml:"host" json:"host"`
		Port     int    `toml:"port" json:"port"`
		SSL      bool   `toml:"ssl" json:"ssl"`
		CertFile string `toml:"cert_file" json:"cert_file"`
		KeyFile  string `toml:"key_file" json:"key_file"`
		Auth     struct {
			Enabled bool   `toml:"enabled" json:"enabled"`
			Token   string `toml:"token" json:"token"`
		} `toml:"auth" json:"auth"`
	} `toml:"api" json:"api"`

	// Настройки логирования
	Logging struct {
		Level      string `toml:"level" json:"level"`
		Output     string `toml:"output" json:"output"`
		MaxSize    int    `toml:"max_size" json:"max_size"`
		MaxBackups int    `toml:"max_backups" json:"max_backups"`
		MaxAge     int    `toml:"max_age" json:"max_age"`
		Compress   bool   `toml:"compress" json:"compress"`
	} `toml:"logging" json:"logging"`

	// Настройки мониторинга
	Monitoring struct {
		Enabled    bool   `toml:"enabled" json:"enabled"`
		Port       int    `toml:"port" json:"port"`
		MetricsURL string `toml:"metrics_url" json:"metrics_url"`
		HealthCheck struct {
			Enabled  bool   `toml:"enabled" json:"enabled"`
			Interval string `toml:"interval" json:"interval"`
			Timeout  string `toml:"timeout" json:"timeout"`
		} `toml:"health_check" json:"health_check"`
	} `toml:"monitoring" json:"monitoring"`

	// Настройки игрового режима
	Gaming struct {
		Enabled            bool   `toml:"enabled" json:"enabled"`
		QoS                bool   `toml:"qos" json:"qos"`
		TrafficShaping     bool   `toml:"traffic_shaping" json:"traffic_shaping"`
		LatencyOptimization bool  `toml:"latency_optimization" json:"latency_optimization"`
		PacketPrioritization bool `toml:"packet_prioritization" json:"packet_prioritization"`
		MaxLatency        int    `toml:"max_latency" json:"max_latency"`
		MaxJitter         int    `toml:"max_jitter" json:"max_jitter"`
		MaxPacketLoss     float64 `toml:"max_packet_loss" json:"max_packet_loss"`
	} `toml:"gaming" json:"gaming"`

	// Настройки AI ассистента
	AIAssistant struct {
		Enabled          bool     `toml:"enabled" json:"enabled"`
		Model            string   `toml:"model" json:"model"`
		LearningRate     float64  `toml:"learning_rate" json:"learning_rate"`
		AnomalyDetection bool     `toml:"anomaly_detection" json:"anomaly_detection"`
		Optimization     bool     `toml:"optimization" json:"optimization"`
		SecurityScan     bool     `toml:"security_scan" json:"security_scan"`
		Notification     bool     `toml:"notification" json:"notification"`
	} `toml:"ai_assistant" json:"ai_assistant"`
}

// Profile представляет профиль пользователя
type Profile struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	DisplayName  string       `json:"display_name"`
	Email        string       `json:"email"`
	Avatar       string       `json:"avatar"`
	Networks     []NetworkInfo `json:"networks"`
	Settings     UserSettings `json:"settings"`
	Security     SecurityInfo `json:"security"`
	CreatedAt    time.Time    `json:"created_at"`
	UpdatedAt    time.Time    `json:"updated_at"`
	LastLogin    time.Time    `json:"last_login"`
	IsActive     bool         `json:"is_active"`
	Version      string       `json:"version"`
}

// NetworkInfo представляет информацию о сети
type NetworkInfo struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Owner       string    `json:"owner"`
	Role        string    `json:"role"` // owner, admin, member
	JoinedAt    time.Time `json:"joined_at"`
	IsDefault   bool      `json:"is_default"`
	PeersCount  int       `json:"peers_count"`
	Online      bool      `json:"online"`
	Public      bool      `json:"public"`
	Encrypted   bool      `json:"encrypted"`
	Settings    NetworkSettings `json:"settings"`
}

// UserSettings представляет настройки пользователя
type UserSettings struct {
	Theme             string   `json:"theme"`
	Language          string   `json:"language"`
	Notifications     bool     `json:"notifications"`
	AutoConnect       bool     `json:"auto_connect"`
	AutoStart         bool     `json:"auto_start"`
	GamingMode        bool     `json:"gaming_mode"`
	AIAssistant       bool     `json:"ai_assistant"`
	TrafficStats      bool     `json:"traffic_stats"`
	BandwidthLimit    int      `json:"bandwidth_limit"`
	ConnectionTimeout int      `json:"connection_timeout"`
	PreferredDNS      []string `json:"preferred_dns"`
	ProxySettings     ProxySettings `json:"proxy_settings"`
}

// SecurityInfo представляет информацию о безопасности
type SecurityInfo struct {
	TwoFactorEnabled bool      `json:"two_factor_enabled"`
	TwoFactorSecret  string    `json:"two_factor_secret"`
	BackupCodes      []string  `json:"backup_codes"`
	LastPasswordChange time.Time `json:"last_password_change"`
	TrustedDevices   []TrustedDevice `json:"trusted_devices"`
	SecurityQuestions []SecurityQuestion `json:"security_questions"`
	EncryptionKey    string    `json:"encryption_key"`
}

// Manager управляет конфигурацией
type Manager struct {
	config    *Config
	profile   *Profile
	configDir string
	mu        sync.RWMutex
	logger    *utils.Logger
	encryptor *Encryptor
}

// NewManager создает новый менеджер конфигурации
func NewManager() (*Manager, error) {
	logger := utils.NewLogger("config")

	// Определяем директорию конфигурации
	configDir, err := getConfigDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get config dir: %v", err)
	}

	// Создаем директории, если их нет
	dirs := []string{
		configDir,
		filepath.Join(configDir, "profiles"),
		filepath.Join(configDir, "networks"),
		filepath.Join(configDir, "keys"),
		filepath.Join(configDir, "backups"),
		filepath.Join(configDir, "logs"),
	}

	for _, dir := range dirs {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create dir %s: %v", dir, err)
		}
	}

	// Создаем менеджер
	mgr := &Manager{
		configDir: configDir,
		logger:    logger,
		encryptor: NewEncryptor(),
	}

	// Загружаем конфигурацию
	if err := mgr.loadConfig(); err != nil {
		return nil, err
	}

	// Загружаем профиль
	if err := mgr.loadProfile(); err != nil {
		return nil, err
	}

	return mgr, nil
}

// Load загружает конфигурацию из файла
func Load(path string) (*Config, error) {
	if path == "" {
		path = getDefaultConfigPath()
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %v", err)
	}

	// Устанавливаем значения по умолчанию
	setDefaults(&config)

	return &config, nil
}

// Save сохраняет конфигурацию
func (m *Manager) Save() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Сохраняем основную конфигурацию
	configPath := filepath.Join(m.configDir, "config.json")
	data, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}

	if err := os.WriteFile(configPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	// Сохраняем профиль
	if err := m.saveProfile(); err != nil {
		return fmt.Errorf("failed to save profile: %v", err)
	}

	m.logger.Info("Configuration saved")
	return nil
}

// GetConfig возвращает конфигурацию
func (m *Manager) GetConfig() *Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.config
}

// UpdateConfig обновляет конфигурацию
func (m *Manager) UpdateConfig(updater func(*Config)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	updater(m.config)
	m.config.UpdatedAt = time.Now()

	return m.Save()
}

// GetProfile возвращает текущий профиль
func (m *Manager) GetProfile() *Profile {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.profile
}

// UpdateProfile обновляет профиль
func (m *Manager) UpdateProfile(updater func(*Profile)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	updater(m.profile)
	m.profile.UpdatedAt = time.Now()

	return m.saveProfile()
}

// CreateProfile создает новый профиль
func (m *Manager) CreateProfile(name, password string) (*Profile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверяем, не существует ли уже профиль с таким именем
	profilePath := filepath.Join(m.configDir, "profiles", name+".json")
	if _, err := os.Stat(profilePath); err == nil {
		return nil, fmt.Errorf("profile already exists")
	}

	// Генерируем ID профиля
	profileID := generateID()

	// Создаем профиль
	profile := &Profile{
		ID:          profileID,
		Name:        name,
		DisplayName: name,
		Networks:    []NetworkInfo{},
		Settings: UserSettings{
			Theme:         "dark",
			Language:      "en",
			Notifications: true,
			AutoConnect:   false,
			GamingMode:    false,
			AIAssistant:   true,
			TrafficStats:  true,
		},
		Security: SecurityInfo{
			TwoFactorEnabled: false,
			TrustedDevices:   []TrustedDevice{},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		IsActive:  true,
		Version:   "1.0",
	}

	// Шифруем профиль, если указан пароль
	if password != "" {
		encryptedData, err := m.encryptor.Encrypt(profile, password)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt profile: %v", err)
		}

		if err := os.WriteFile(profilePath, encryptedData, 0600); err != nil {
			return nil, fmt.Errorf("failed to save profile: %v", err)
		}
	} else {
		// Сохраняем без шифрования
		data, err := json.MarshalIndent(profile, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("failed to marshal profile: %v", err)
		}

		if err := os.WriteFile(profilePath, data, 0600); err != nil {
			return nil, fmt.Errorf("failed to save profile: %v", err)
		}
	}

	m.profile = profile
	m.logger.Info("Profile created", "name", name)
	return profile, nil
}

// SwitchProfile переключает профиль
func (m *Manager) SwitchProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	profilePath := filepath.Join(m.configDir, "profiles", name+".json")
	data, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %v", err)
	}

	var profile Profile
	
	// Пытаемся расшифровать (если зашифровано)
	decrypted, err := m.encryptor.TryDecrypt(data, "")
	if err == nil {
		// Успешно расшифровано без пароля (не зашифровано)
		if err := json.Unmarshal(decrypted, &profile); err != nil {
			return fmt.Errorf("failed to parse profile: %v", err)
		}
	} else {
		// Запрашиваем пароль для расшифровки
		// В реальном приложении здесь был бы запрос пароля
		return fmt.Errorf("profile is encrypted, password required")
	}

	m.profile = &profile
	m.logger.Info("Profile switched", "name", name)
	return nil
}

// ListProfiles возвращает список профилей
func (m *Manager) ListProfiles() ([]string, error) {
	profilesDir := filepath.Join(m.configDir, "profiles")
	files, err := os.ReadDir(profilesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read profiles dir: %v", err)
	}

	var profiles []string
	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			name := file.Name()[:len(file.Name())-5] // Убираем .json
			profiles = append(profiles, name)
		}
	}

	return profiles, nil
}

// DeleteProfile удаляет профиль
func (m *Manager) DeleteProfile(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Нельзя удалить текущий профиль
	if m.profile != nil && m.profile.Name == name {
		return fmt.Errorf("cannot delete current profile")
	}

	profilePath := filepath.Join(m.configDir, "profiles", name+".json")
	if err := os.Remove(profilePath); err != nil {
		return fmt.Errorf("failed to delete profile: %v", err)
	}

	m.logger.Info("Profile deleted", "name", name)
	return nil
}

// Backup создает резервную копию конфигурации
func (m *Manager) Backup() (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	backupDir := filepath.Join(m.configDir, "backups")
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create backup dir: %v", err)
	}

	// Создаем имя файла с временной меткой
	timestamp := time.Now().Format("2006-01-02_15-04-05")
	backupFile := filepath.Join(backupDir, fmt.Sprintf("backup_%s.tar.gz", timestamp))

	// Архивируем конфигурацию
	// (реализация архивирования опущена для краткости)

	m.logger.Info("Backup created", "file", backupFile)
	return backupFile, nil
}

// Restore восстанавливает конфигурацию из резервной копии
func (m *Manager) Restore(backupFile string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Проверяем существование файла
	if _, err := os.Stat(backupFile); err != nil {
		return fmt.Errorf("backup file not found: %v", err)
	}

	// Восстанавливаем из резервной копии
	// (реализация восстановления опущена для краткости)

	// Перезагружаем конфигурацию
	if err := m.loadConfig(); err != nil {
		return fmt.Errorf("failed to reload config: %v", err)
	}

	if err := m.loadProfile(); err != nil {
		return fmt.Errorf("failed to reload profile: %v", err)
	}

	m.logger.Info("Configuration restored", "file", backupFile)
	return nil
}

// Внутренние методы

func (m *Manager) loadConfig() error {
	configPath := filepath.Join(m.configDir, "config.json")
	
	// Если файл не существует, создаем конфигурацию по умолчанию
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		m.config = defaultConfig()
		return m.Save()
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %v", err)
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("failed to parse config: %v", err)
	}

	m.config = &config
	return nil
}

func (m *Manager) loadProfile() error {
	// Ищем профиль по умолчанию
	profilePath := filepath.Join(m.configDir, "profiles", "default.json")
	
	if _, err := os.Stat(profilePath); os.IsNotExist(err) {
		// Создаем профиль по умолчанию
		profile, err := m.CreateProfile("default", "")
		if err != nil {
			return err
		}
		m.profile = profile
		return nil
	}

	data, err := os.ReadFile(profilePath)
	if err != nil {
		return fmt.Errorf("failed to read profile: %v", err)
	}

	var profile Profile
	if err := json.Unmarshal(data, &profile); err != nil {
		return fmt.Errorf("failed to parse profile: %v", err)
	}

	m.profile = &profile
	return nil
}

func (m *Manager) saveProfile() error {
	if m.profile == nil {
		return nil
	}

	profilePath := filepath.Join(m.configDir, "profiles", m.profile.Name+".json")
	data, err := json.MarshalIndent(m.profile, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profile: %v", err)
	}

	if err := os.WriteFile(profilePath, data, 0600); err != nil {
		return fmt.Errorf("failed to save profile: %v", err)
	}

	return nil
}

// Вспомогательные функции

func getConfigDir() (string, error) {
	// Проверяем переменную окружения
	if dir := os.Getenv("SUPRESSOR_CONFIG_DIR"); dir != "" {
		return dir, nil
	}

	// Используем домашнюю директорию пользователя
	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/supressor", nil
	}

	return filepath.Join(home, ".config", "supressor"), nil
}

func getDefaultConfigPath() string {
	configDir, _ := getConfigDir()
	return filepath.Join(configDir, "config.json")
}

func defaultConfig() *Config {
	config := &Config{
		AppName:     "Supressor",
		Version:     "1.0.0",
		Environment: "production",
	}

	// Настройки сети по умолчанию
	config.Network.Interface = "supressor0"
	config.Network.Port = 51820
	config.Network.MTU = 1420
	config.Network.DNS = []string{"1.1.1.1", "8.8.8.8"}
	config.Network.AllowedIPs = []string{"0.0.0.0/0", "::/0"}
	config.Network.PersistentKeepalive = 25
	config.Network.Table = "auto"

	// Настройки безопасности по умолчанию
	config.Security.EncryptionAlgorithm = "chacha20-poly1305"
	config.Security.KeyRotationInterval = "7d"
	config.Security.SessionTimeout = "24h"
	config.Security.MaxLoginAttempts = 5
	config.Security.Require2FA = false

	// Настройки базы данных по умолчанию
	config.Database.Path = filepath.Join(getConfigDirDefault(), "supressor.db")
	config.Database.Encrypted = true
	config.Database.Backup.Enabled = true
	config.Database.Backup.Interval = "24h"
	config.Database.Backup.KeepDays = 7

	// Настройки API по умолчанию
	config.API.Enabled = true
	config.API.Host = "127.0.0.1"
	config.API.Port = 8080
	config.API.SSL = false
	config.API.Auth.Enabled = true

	// Настройки логирования по умолчанию
	config.Logging.Level = "info"
	config.Logging.Output = "file"
	config.Logging.MaxSize = 100 // MB
	config.Logging.MaxBackups = 5
	config.Logging.MaxAge = 30 // days
	config.Logging.Compress = true

	// Настройки мониторинга по умолчанию
	config.Monitoring.Enabled = true
	config.Monitoring.Port = 9090
	config.Monitoring.MetricsURL = "/metrics"
	config.Monitoring.HealthCheck.Enabled = true
	config.Monitoring.HealthCheck.Interval = "30s"
	config.Monitoring.HealthCheck.Timeout = "5s"

	// Настройки игрового режима по умолчанию
	config.Gaming.Enabled = true
	config.Gaming.QoS = true
	config.Gaming.TrafficShaping = true
	config.Gaming.LatencyOptimization = true
	config.Gaming.PacketPrioritization = true
	config.Gaming.MaxLatency = 100 // ms
	config.Gaming.MaxJitter = 50   // ms
	config.Gaming.MaxPacketLoss = 1.0 // %

	// Настройки AI ассистента по умолчанию
	config.AIAssistant.Enabled = true
	config.AIAssistant.Model = "default"
	config.AIAssistant.LearningRate = 0.01
	config.AIAssistant.AnomalyDetection = true
	config.AIAssistant.Optimization = true
	config.AIAssistant.SecurityScan = true
	config.AIAssistant.Notification = true

	return config
}

func getConfigDirDefault() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "/var/lib/supressor"
	}
	return filepath.Join(home, ".local", "share", "supressor")
}

func setDefaults(config *Config) {
	// Устанавливаем значения по умолчанию для пустых полей
	if config.AppName == "" {
		config.AppName = "Supressor"
	}
	if config.Version == "" {
		config.Version = "1.0.0"
	}
	if config.Environment == "" {
		config.Environment = "production"
	}
	// ... остальные значения по умолчанию
}

func generateID() string {
	// Генерация уникального ID
	// В реальном приложении используйте github.com/google/uuid
	return fmt.Sprintf("%x", time.Now().UnixNano())
}
