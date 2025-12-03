package network

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"supressor/internal/config"
	"supressor/internal/crypto"
	"supressor/internal/storage"
	"supressor/internal/utils"
)

// Manager управляет сетевыми соединениями
type Manager struct {
	ctx         context.Context
	cancel      context.CancelFunc
	config      *config.Config
	profile     *config.Profile
	device      *device.Device
	tunDevice   tun.Device
	peers       map[string]*Peer
	connections map[string]*Connection
	stats       *Stats
	aiAnalyzer  *AIAnalyzer
	gamingMode  *GamingMode
	qos         *QoSManager
	stunClient  *STUNClient
	turnClient  *TURNClient
	discovery   *DiscoveryService
	mu          sync.RWMutex
	eventChan   chan Event
	db          *storage.Database
	isRunning   bool
	startTime   time.Time
	logger      *utils.Logger
}

// Peer представляет подключенного пира
type Peer struct {
	ID              string            `json:"id"`
	Name            string            `json:"name"`
	PublicKey       string            `json:"public_key"`
	Endpoint        *net.UDPAddr      `json:"endpoint"`
	AllowedIPs      []net.IPNet       `json:"allowed_ips"`
	PersistentKeepalive int           `json:"persistent_keepalive"`
	LastHandshake   time.Time         `json:"last_handshake"`
	RxBytes         uint64            `json:"rx_bytes"`
	TxBytes         uint64            `json:"tx_bytes"`
	IsConnected     bool              `json:"is_connected"`
	Latency         time.Duration     `json:"latency"`
	Jitter          time.Duration     `json:"jitter"`
	PacketLoss      float64           `json:"packet_loss"`
	DeviceInfo      *DeviceInfo       `json:"device_info"`
	TrustLevel      TrustLevel        `json:"trust_level"`
	LastSeen        time.Time         `json:"last_seen"`
	ConnectionTime  time.Duration     `json:"connection_time"`
	GeoLocation     *GeoLocation      `json:"geo_location"`
	SecurityScore   float64           `json:"security_score"`
}

// DeviceInfo содержит информацию об устройстве
type DeviceInfo struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	Arch        string `json:"arch"`
	AppVersion  string `json:"app_version"`
	CPU         string `json:"cpu"`
	RAM         uint64 `json:"ram"`
}

// GeoLocation содержит географическую информацию
type GeoLocation struct {
	Country   string  `json:"country"`
	City      string  `json:"city"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
	ISP       string  `json:"isp"`
}

// TrustLevel определяет уровень доверия
type TrustLevel int

const (
	TrustUnknown TrustLevel = iota
	TrustLow
	TrustMedium
	TrustHigh
	TrustSystem
)

// Stats содержит статистику сети
type Stats struct {
	StartTime       time.Time         `json:"start_time"`
	TotalRxBytes    uint64            `json:"total_rx_bytes"`
	TotalTxBytes    uint64            `json:"total_tx_bytes"`
	TotalPackets    uint64            `json:"total_packets"`
	ActivePeers     int               `json:"active_peers"`
	ConnectionTime  time.Duration     `json:"connection_time"`
	Uptime          time.Duration     `json:"uptime"`
	AverageLatency  time.Duration     `json:"average_latency"`
	MaxLatency      time.Duration     `json:"max_latency"`
	MinLatency      time.Duration     `json:"min_latency"`
	AverageJitter   time.Duration     `json:"average_jitter"`
	PacketLoss      float64           `json:"packet_loss"`
	ThroughputUp    uint64            `json:"throughput_up"`   // Байт/сек
	ThroughputDown  uint64            `json:"throughput_down"` // Байт/сек
	ProtocolStats   map[string]uint64 `json:"protocol_stats"`
	TrafficByHour   [24]uint64        `json:"traffic_by_hour"`
	SecurityEvents  []SecurityEvent   `json:"security_events"`
}

// SecurityEvent представляет событие безопасности
type SecurityEvent struct {
	Timestamp time.Time       `json:"timestamp"`
	Type      string          `json:"type"`
	Severity  string          `json:"severity"` // low, medium, high, critical
	Message   string          `json:"message"`
	PeerID    string          `json:"peer_id"`
	Data      json.RawMessage `json:"data"`
}

// Event представляет событие в сети
type Event struct {
	Type      string      `json:"type"`
	PeerID    string      `json:"peer_id"`
	Data      interface{} `json:"data"`
	Timestamp time.Time   `json:"timestamp"`
}

// Connection представляет сетевое соединение
type Connection struct {
	ID           string        `json:"id"`
	PeerID       string        `json:"peer_id"`
	LocalAddr    net.Addr      `json:"local_addr"`
	RemoteAddr   net.Addr      `json:"remote_addr"`
	Protocol     string        `json:"protocol"`
	StartTime    time.Time     `json:"start_time"`
	LastActivity time.Time     `json:"last_activity"`
	BytesSent    uint64        `json:"bytes_sent"`
	BytesReceived uint64       `json:"bytes_received"`
	IsEncrypted  bool          `json:"is_encrypted"`
	EncryptionAlgo string      `json:"encryption_algo"`
}

// NetworkConfig содержит конфигурацию сети
type NetworkConfig struct {
	Name          string      `json:"name"`
	PrivateKey    string      `json:"private_key"`
	PublicKey     string      `json:"public_key"`
	Address       net.IPNet   `json:"address"`
	DNS           []net.IP    `json:"dns"`
	MTU           int         `json:"mtu"`
	ListenPort    int         `json:"listen_port"`
	FirewallMark  int         `json:"firewall_mark"`
	Table         string      `json:"table"`
	PreUp         string      `json:"pre_up"`
	PostUp        string      `json:"post_up"`
	PreDown       string      `json:"pre_down"`
	PostDown      string      `json:"post_down"`
	SaveConfig    bool        `json:"save_config"`
	GameMode      bool        `json:"game_mode"`
	Encryption    string      `json:"encryption"`
	Compression   bool        `json:"compression"`
}

// NewManager создает новый сетевой менеджер
func NewManager(ctx context.Context, cfg *config.Config, profile *config.Profile) (*Manager, error) {
	ctx, cancel := context.WithCancel(ctx)

	logger := utils.NewLogger("network")

	// Инициализация базы данных
	db, err := storage.New(cfg.Database.Path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to init database: %v", err)
	}

	// Генерация ключей
	privateKey, publicKey, err := crypto.GenerateWireGuardKeys()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to generate keys: %v", err)
	}

	// Конфигурация сети
	networkConfig := &NetworkConfig{
		Name:         "supressor0",
		PrivateKey:   privateKey,
		PublicKey:    publicKey,
		Address: net.IPNet{
			IP:   net.IPv4(10, 0, 0, 1),
			Mask: net.CIDRMask(24, 32),
		},
		DNS: []net.IP{
			net.IPv4(1, 1, 1, 1),
			net.IPv4(8, 8, 8, 8),
		},
		MTU:           cfg.Network.MTU,
		ListenPort:    cfg.Network.Port,
		SaveConfig:    true,
		GameMode:      cfg.Gaming.Enabled,
		Encryption:    cfg.Security.EncryptionAlgorithm,
		Compression:   true,
	}

	mgr := &Manager{
		ctx:         ctx,
		cancel:      cancel,
		config:      cfg,
		profile:     profile,
		peers:       make(map[string]*Peer),
		connections: make(map[string]*Connection),
		stats: &Stats{
			StartTime:     time.Now(),
			ProtocolStats: make(map[string]uint64),
		},
		eventChan:  make(chan Event, 100),
		db:         db,
		isRunning:  false,
		startTime:  time.Now(),
		logger:     logger,
	}

	// Инициализация компонентов
	if err := mgr.initComponents(networkConfig); err != nil {
		cancel()
		return nil, err
	}

	return mgr, nil
}

func (m *Manager) initComponents(networkConfig *NetworkConfig) error {
	// Инициализация AI анализатора
	m.aiAnalyzer = NewAIAnalyzer(m)

	// Инициализация игрового режима
	m.gamingMode = NewGamingMode(m)

	// Инициализация QoS
	m.qos = NewQoSManager(m)

	// Инициализация STUN/TURN клиентов
	m.stunClient = NewSTUNClient()
	m.turnClient = NewTURNClient()

	// Инициализация сервиса обнаружения
	m.discovery = NewDiscoveryService(m)

	return nil
}

// Start запускает сетевой менеджер
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isRunning {
		return fmt.Errorf("network manager is already running")
	}

	// Создание TUN устройства
	tunDevice, err := tun.CreateTUN("supressor0", m.config.Network.MTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN device: %v", err)
	}
	m.tunDevice = tunDevice

	// Создание WireGuard устройства
	logger := &device.Logger{
		Verbosef: func(format string, args ...interface{}) {
			m.logger.Debug(fmt.Sprintf(format, args...))
		},
		Errorf: func(format string, args ...interface{}) {
			m.logger.Error(fmt.Sprintf(format, args...))
			m.logSecurityEvent("wireguard_error", "medium",
				fmt.Sprintf(format, args...), "")
		},
	}

	dev := device.NewDevice(m.tunDevice, logger)
	m.device = dev

	// Применение конфигурации
	if err := m.applyConfig(); err != nil {
		dev.Close()
		return fmt.Errorf("failed to apply config: %v", err)
	}

	// Запуск устройства
	dev.Up()

	// Запуск мониторинга
	go m.monitoringLoop()
	go m.peerManagementLoop()
	go m.securityMonitoringLoop()
	go m.trafficAnalysisLoop()

	// Запуск сервиса обнаружения
	go m.discovery.Start()

	// Если включен игровой режим
	if m.config.Gaming.Enabled {
		go m.gamingMode.Start()
	}

	m.isRunning = true
	m.broadcastEvent(Event{
		Type:      "manager_started",
		Timestamp: time.Now(),
	})

	m.logger.Info("Network manager started")
	return nil
}

// Stop останавливает сетевой менеджер
func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isRunning {
		return nil
	}

	m.cancel()

	if m.device != nil {
		m.device.Down()
		m.device.Close()
	}

	if m.discovery != nil {
		m.discovery.Stop()
	}

	if m.gamingMode != nil {
		m.gamingMode.Stop()
	}

	m.isRunning = false

	// Сохраняем конфигурацию
	if err := m.saveConfig(); err != nil {
		m.logger.Error("Failed to save config", "error", err)
	}

	m.logger.Info("Network manager stopped")
	return nil
}

// CreateNetwork создает новую сеть
func (m *Manager) CreateNetwork(name, password string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Генерация ID сети
	networkID := generateNetworkID()

	// Создание конфигурации сети
	networkConfig := &NetworkConfig{
		Name:        name,
		PrivateKey:  generatePrivateKey(),
		PublicKey:   generatePublicKey(),
		Address: net.IPNet{
			IP:   generateNetworkIP(),
			Mask: net.CIDRMask(24, 32),
		},
		DNS:        m.config.Network.DNS,
		MTU:        m.config.Network.MTU,
		ListenPort: m.config.Network.Port,
		GameMode:   m.config.Gaming.Enabled,
		Encryption: m.config.Security.EncryptionAlgorithm,
	}

	// Сохранение сети в БД
	if err := m.db.SaveNetwork(networkID, networkConfig, password); err != nil {
		return "", fmt.Errorf("failed to save network: %v", err)
	}

	// Добавление сети в профиль
	m.profile.Networks = append(m.profile.Networks, config.NetworkInfo{
		ID:   networkID,
		Name: name,
		Role: "owner",
	})

	m.broadcastEvent(Event{
		Type:      "network_created",
		Data:      networkConfig,
		Timestamp: time.Now(),
	})

	m.logger.Info("Network created", "name", name, "id", networkID)
	return networkID, nil
}

// JoinNetwork присоединяется к сети
func (m *Manager) JoinNetwork(networkID, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Загрузка сети из БД
	networkConfig, err := m.db.LoadNetwork(networkID, password)
	if err != nil {
		return fmt.Errorf("failed to load network: %v", err)
	}

	// Применение конфигурации сети
	if err := m.applyNetworkConfig(networkConfig); err != nil {
		return fmt.Errorf("failed to apply network config: %v", err)
	}

	// Добавление сети в профиль
	m.profile.Networks = append(m.profile.Networks, config.NetworkInfo{
		ID:   networkID,
		Name: networkConfig.Name,
		Role: "member",
	})

	m.broadcastEvent(Event{
		Type:      "network_joined",
		Data:      networkConfig,
		Timestamp: time.Now(),
	})

	m.logger.Info("Joined network", "id", networkID)
	return nil
}

// AddPeer добавляет пира в сеть
func (m *Manager) AddPeer(name, publicKey string, allowedIPs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer := &Peer{
		ID:        generatePeerID(),
		Name:      name,
		PublicKey: publicKey,
		AllowedIPs: parseIPNets(allowedIPs),
		IsConnected: false,
		TrustLevel: TrustLow,
		LastSeen:   time.Now(),
	}

	m.peers[peer.ID] = peer

	// Добавление пира в WireGuard
	peerConfig := fmt.Sprintf(`
[Peer]
PublicKey = %s
AllowedIPs = %s
`, publicKey, joinIPNets(allowedIPs))

	if err := m.device.IpcSet(peerConfig); err != nil {
		delete(m.peers, peer.ID)
		return fmt.Errorf("failed to add peer to wireguard: %v", err)
	}

	// Сохранение в БД
	if err := m.db.SavePeer(peer); err != nil {
		m.logger.Error("Failed to save peer to database", "error", err)
	}

	m.broadcastEvent(Event{
		Type:      "peer_added",
		PeerID:    peer.ID,
		Data:      peer,
		Timestamp: time.Now(),
	})

	m.logger.Info("Peer added", "name", name, "id", peer.ID)
	return nil
}

// RemovePeer удаляет пира из сети
func (m *Manager) RemovePeer(peerID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, exists := m.peers[peerID]
	if !exists {
		return fmt.Errorf("peer not found")
	}

	// Удаление пира из WireGuard
	removeConfig := fmt.Sprintf(`
[Peer]
PublicKey = %s
Remove = true
`, peer.PublicKey)

	if err := m.device.IpcSet(removeConfig); err != nil {
		return fmt.Errorf("failed to remove peer from wireguard: %v", err)
	}

	delete(m.peers, peerID)

	// Удаление из БД
	if err := m.db.DeletePeer(peerID); err != nil {
		m.logger.Error("Failed to delete peer from database", "error", err)
	}

	m.broadcastEvent(Event{
		Type:      "peer_removed",
		PeerID:    peerID,
		Timestamp: time.Now(),
	})

	m.logger.Info("Peer removed", "id", peerID)
	return nil
}

// GetStatus возвращает статус сети
func (m *Manager) GetStatus() Status {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Подсчет активных пиров
	activePeers := 0
	for _, peer := range m.peers {
		if peer.IsConnected {
			activePeers++
		}
	}

	// Расчет статистики
	var totalLatency time.Duration
	var maxLatency time.Duration
	minLatency := time.Hour
	peerCount := 0

	for _, peer := range m.peers {
		if peer.IsConnected {
			totalLatency += peer.Latency
			if peer.Latency > maxLatency {
				maxLatency = peer.Latency
			}
			if peer.Latency < minLatency && peer.Latency > 0 {
				minLatency = peer.Latency
			}
			peerCount++
		}
	}

	avgLatency := time.Duration(0)
	if peerCount > 0 {
		avgLatency = totalLatency / time.Duration(peerCount)
	}

	return Status{
		Connected:   m.isRunning,
		NetworkName: m.getNetworkName(),
		PeerCount:   activePeers,
		TxBytes:     m.stats.TotalTxBytes,
		RxBytes:     m.stats.TotalRxBytes,
		Uptime:      time.Since(m.startTime).String(),
		AvgLatency:  avgLatency,
		MaxLatency:  maxLatency,
		MinLatency:  minLatency,
		PacketLoss:  m.stats.PacketLoss,
	}
}

// ListPeers возвращает список пиров
func (m *Manager) ListPeers() []Peer {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peers := make([]Peer, 0, len(m.peers))
	for _, peer := range m.peers {
		peers = append(peers, *peer)
	}
	return peers
}

// GetPeer возвращает информацию о пире
func (m *Manager) GetPeer(peerID string) (*Peer, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	peer, exists := m.peers[peerID]
	if !exists {
		return nil, fmt.Errorf("peer not found")
	}
	return peer, nil
}

// UpdatePeer обновляет информацию о пире
func (m *Manager) UpdatePeer(peerID string, updater func(*Peer)) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, exists := m.peers[peerID]
	if !exists {
		return fmt.Errorf("peer not found")
	}

	updater(peer)
	peer.LastSeen = time.Now()

	// Сохранение в БД
	if err := m.db.SavePeer(peer); err != nil {
		m.logger.Error("Failed to save peer to database", "error", err)
	}

	m.broadcastEvent(Event{
		Type:      "peer_updated",
		PeerID:    peerID,
		Data:      peer,
		Timestamp: time.Now(),
	})

	return nil
}

// SetPeerTrustLevel устанавливает уровень доверия пира
func (m *Manager) SetPeerTrustLevel(peerID string, level TrustLevel) error {
	return m.UpdatePeer(peerID, func(p *Peer) {
		p.TrustLevel = level
	})
}

// BanPeer блокирует пира
func (m *Manager) BanPeer(peerID string, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	peer, exists := m.peers[peerID]
	if !exists {
		return fmt.Errorf("peer not found")
	}

	// Добавление в черный список
	if err := m.db.BanPeer(peerID, peer.PublicKey, reason); err != nil {
		return fmt.Errorf("failed to ban peer: %v", err)
	}

	// Удаление пира
	delete(m.peers, peerID)

	m.broadcastEvent(Event{
		Type:      "peer_banned",
		PeerID:    peerID,
		Data:      map[string]string{"reason": reason},
		Timestamp: time.Now(),
	})

	m.logger.Warn("Peer banned", "id", peerID, "reason", reason)
	return nil
}

// GetStats возвращает статистику сети
func (m *Manager) GetStats() *Stats {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Создаем копию статистики
	stats := *m.stats
	return &stats
}

// GetEvents возвращает канал событий
func (m *Manager) GetEvents() <-chan Event {
	return m.eventChan
}

// EnableGamingMode включает игровой режим
func (m *Manager) EnableGamingMode() error {
	if m.gamingMode == nil {
		return fmt.Errorf("gaming mode not initialized")
	}

	m.gamingMode.Enable()
	m.config.Gaming.Enabled = true

	m.broadcastEvent(Event{
		Type:      "gaming_mode_enabled",
		Timestamp: time.Now(),
	})

	m.logger.Info("Gaming mode enabled")
	return nil
}

// DisableGamingMode выключает игровой режим
func (m *Manager) DisableGamingMode() error {
	if m.gamingMode == nil {
		return fmt.Errorf("gaming mode not initialized")
	}

	m.gamingMode.Disable()
	m.config.Gaming.Enabled = false

	m.broadcastEvent(Event{
		Type:      "gaming_mode_disabled",
		Timestamp: time.Now(),
	})

	m.logger.Info("Gaming mode disabled")
	return nil
}

// SetQoS настраивает Quality of Service
func (m *Manager) SetQoS(config QoSConfig) error {
	if m.qos == nil {
		return fmt.Errorf("qos not initialized")
	}

	return m.qos.SetConfig(config)
}

// PerformSecurityScan выполняет проверку безопасности
func (m *Manager) PerformSecurityScan() (*SecurityReport, error) {
	if m.aiAnalyzer == nil {
		return nil, fmt.Errorf("ai analyzer not initialized")
	}

	return m.aiAnalyzer.PerformSecurityScan()
}

// OptimizeNetwork выполняет оптимизацию сети
func (m *Manager) OptimizeNetwork() error {
	if m.aiAnalyzer == nil {
		return fmt.Errorf("ai analyzer not initialized")
	}

	return m.aiAnalyzer.OptimizeNetwork()
}

// Внутренние методы

func (m *Manager) applyConfig() error {
	// Формирование конфигурации WireGuard
	configStr := fmt.Sprintf(`
[Interface]
PrivateKey = %s
Address = %s
DNS = %s
MTU = %d
ListenPort = %d
`, m.getPrivateKey(),
		m.getAddress(),
		joinIPs(m.config.Network.DNS),
		m.config.Network.MTU,
		m.config.Network.Port)

	// Добавление pre-up/post-up команд
	if len(m.config.Network.PreUp) > 0 {
		configStr += fmt.Sprintf("PreUp = %s\n", m.config.Network.PreUp[0])
	}
	if len(m.config.Network.PostUp) > 0 {
		configStr += fmt.Sprintf("PostUp = %s\n", m.config.Network.PostUp[0])
	}

	return m.device.IpcSet(configStr)
}

func (m *Manager) applyNetworkConfig(networkConfig *NetworkConfig) error {
	configStr := fmt.Sprintf(`
[Interface]
PrivateKey = %s
Address = %s
DNS = %s
MTU = %d
ListenPort = %d
`, networkConfig.PrivateKey,
		networkConfig.Address.String(),
		joinIPs(networkConfig.DNS),
		networkConfig.MTU,
		networkConfig.ListenPort)

	return m.device.IpcSet(configStr)
}

func (m *Manager) monitoringLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	latencyTicker := time.NewTicker(10 * time.Second)
	defer latencyTicker.Stop()

	statsTicker := time.NewTicker(5 * time.Second)
	defer statsTicker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.updatePeerStatus()
		case <-latencyTicker.C:
			m.measurePeerLatency()
		case <-statsTicker.C:
			m.updateStatistics()
			m.checkForAnomalies()
		}
	}
}

func (m *Manager) peerManagementLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.cleanupInactivePeers()
			m.checkPeerTrustLevels()
		}
	}
}

func (m *Manager) securityMonitoringLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.performSecurityScan()
		}
	}
}

func (m *Manager) trafficAnalysisLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			m.analyzeTrafficPatterns()
		}
	}
}

func (m *Manager) updatePeerStatus() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, peer := range m.peers {
		wasConnected := peer.IsConnected
		
		// Проверка времени последнего handshake
		timeSinceHandshake := time.Since(peer.LastHandshake)
		peer.IsConnected = timeSinceHandshake < 180*time.Second // 3 минуты

		if wasConnected != peer.IsConnected {
			eventType := "peer_connected"
			if !peer.IsConnected {
				eventType = "peer_disconnected"
			}

			m.broadcastEvent(Event{
				Type:      eventType,
				PeerID:    peer.ID,
				Data:      peer,
				Timestamp: time.Now(),
			})
		}

		// Обновление статистики
		if peer.IsConnected {
			peer.ConnectionTime += time.Second
		}
	}
}

func (m *Manager) measurePeerLatency() {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, peer := range m.peers {
		if !peer.IsConnected || peer.Endpoint == nil {
			continue
		}

		// Измерение ping до пира
		latency, err := m.pingPeer(peer)
		if err != nil {
			peer.PacketLoss += 0.1
			continue
		}

		// Обновление метрик
		peer.Latency = latency
		
		// Расчет джиттера
		if peer.Latency > 0 {
			if peer.Jitter == 0 {
				peer.Jitter = latency
			} else {
				// Экспоненциальное сглаживание для джиттера
				peer.Jitter = time.Duration(float64(peer.Jitter)*0.9 + float64(latency)*0.1)
			}
		}

		peer.PacketLoss *= 0.9 // Экспоненциальное затухание
	}
}

func (m *Manager) updateStatistics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Получение статистики от устройства
	stats, err := m.device.IpcGet()
	if err != nil {
		m.logger.Error("Failed to get device stats", "error", err)
		return
	}

	// Парсинг статистики
	// (упрощенно, в реальности нужно парсить вывод ipc)
	
	// Обновление общей статистики
	m.stats.Uptime = time.Since(m.stats.StartTime)
	m.stats.ActivePeers = 0
	
	var totalLatency time.Duration
	var maxLatency time.Duration
	minLatency := time.Hour
	peerCount := 0

	for _, peer := range m.peers {
		if peer.IsConnected {
			m.stats.ActivePeers++
			
			totalLatency += peer.Latency
			if peer.Latency > maxLatency {
				maxLatency = peer.Latency
			}
			if peer.Latency < minLatency && peer.Latency > 0 {
				minLatency = peer.Latency
			}
			peerCount++
		}
	}

	if peerCount > 0 {
		m.stats.AverageLatency = totalLatency / time.Duration(peerCount)
		m.stats.MaxLatency = maxLatency
		m.stats.MinLatency = minLatency
	}

	// Обновление статистики по часам
	hour := time.Now().Hour()
	m.stats.TrafficByHour[hour] = m.stats.TotalRxBytes + m.stats.TotalTxBytes
}

func (m *Manager) checkForAnomalies() {
	if m.aiAnalyzer == nil {
		return
	}

	anomalies := m.aiAnalyzer.DetectAnomalies(m.stats, m.peers)
	
	for _, anomaly := range anomalies {
		m.logSecurityEvent("anomaly_detected", anomaly.Severity,
			anomaly.Message, anomaly.PeerID)
		
		m.broadcastEvent(Event{
			Type:      "security_alert",
			PeerID:    anomaly.PeerID,
			Data:      anomaly,
			Timestamp: time.Now(),
		})
	}
}

func (m *Manager) cleanupInactivePeers() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for peerID, peer := range m.peers {
		// Удаление пиров, которые не появлялись более 24 часов
		if now.Sub(peer.LastSeen) > 24*time.Hour {
			delete(m.peers, peerID)
			
			// Удаление из БД
			if err := m.db.DeletePeer(peerID); err != nil {
				m.logger.Error("Failed to delete inactive peer", "error", err)
			}
		}
	}
}

func (m *Manager) checkPeerTrustLevels() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, peer := range m.peers {
		// Автоматическое повышение уровня доверия для активных пиров
		if peer.IsConnected && peer.ConnectionTime > time.Hour {
			if peer.TrustLevel < TrustHigh {
				peer.TrustLevel++
				m.logger.Info("Peer trust level increased", 
					"peer", peer.Name, "level", peer.TrustLevel)
			}
		}
	}
}

func (m *Manager) analyzeTrafficPatterns() {
	if m.aiAnalyzer == nil {
		return
	}

	patterns := m.aiAnalyzer.AnalyzeTrafficPatterns(m.stats)
	
	if m.config.Gaming.Enabled {
		m.gamingMode.OptimizeBasedOnPatterns(patterns)
	}
	
	if m.qos != nil {
		m.qos.UpdatePriorities(patterns)
	}
}

func (m *Manager) pingPeer(peer *Peer) (time.Duration, error) {
	conn, err := net.DialUDP("udp", nil, peer.Endpoint)
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Создание ping пакета
	pingData := []byte("SUPRESSOR_PING")
	start := time.Now()

	// Отправка
	if _, err := conn.Write(pingData); err != nil {
		return 0, err
	}

	// Чтение ответа с таймаутом
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buffer := make([]byte, 1500)
	n, err := conn.Read(buffer)
	if err != nil {
		return 0, err
	}

	// Проверка ответа
	if string(buffer[:n]) != "SUPRESSOR_PONG" {
		return 0, fmt.Errorf("invalid response")
	}

	return time.Since(start), nil
}

func (m *Manager) logSecurityEvent(eventType, severity, message, peerID string) {
	event := SecurityEvent{
		Timestamp: time.Now(),
		Type:      eventType,
		Severity:  severity,
		Message:   message,
		PeerID:    peerID,
	}

	m.stats.SecurityEvents = append(m.stats.SecurityEvents, event)
	
	// Сохранение в БД
	m.db.SaveSecurityEvent(event)
	
	// Ограничение количества хранимых событий
	if len(m.stats.SecurityEvents) > 1000 {
		m.stats.SecurityEvents = m.stats.SecurityEvents[100:]
	}
}

func (m *Manager) broadcastEvent(event Event) {
	select {
	case m.eventChan <- event:
		// Событие отправлено
	default:
		// Канал полон, пропускаем событие
	}
}

func (m *Manager) getNetworkName() string {
	if len(m.profile.Networks) > 0 {
		return m.profile.Networks[0].Name
	}
	return "No Network"
}

func (m *Manager) getPrivateKey() string {
	// В реальном приложении ключ должен храниться безопасно
	return "placeholder_private_key"
}

func (m *Manager) getAddress() string {
	return "10.0.0.1/24"
}

func (m *Manager) saveConfig() error {
	// Сохранение конфигурации в файл
	configData, err := json.MarshalIndent(m.config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %v", err)
	}
	
	configPath := filepath.Join(m.configDir, "network_config.json")
	return os.WriteFile(configPath, configData, 0600)
}

// Вспомогательные функции

func generateNetworkID() string {
	return fmt.Sprintf("net_%x", time.Now().UnixNano())
}

func generatePeerID() string {
	return fmt.Sprintf("peer_%x", time.Now().
