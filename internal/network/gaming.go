package network

import (
	"fmt"
	"time"
)

// GamingMode управляет игровым режимом
type GamingMode struct {
	manager      *Manager
	isEnabled    bool
	config       GamingConfig
	optimizer    *TrafficOptimizer
	qos          *QoSController
	monitor      *LatencyMonitor
	logger       *utils.Logger
}

// GamingConfig содержит конфигурацию игрового режима
type GamingConfig struct {
	Enabled                bool    `json:"enabled"`
	MaxLatency            int     `json:"max_latency"`    // ms
	MaxJitter             int     `json:"max_jitter"`     // ms
	MaxPacketLoss         float64 `json:"max_packet_loss"` // %
	TrafficShaping        bool    `json:"traffic_shaping"`
	PacketPrioritization  bool    `json:"packet_prioritization"`
	UDPOptimization       bool    `json:"udp_optimization"`
	TCPOptimization       bool    `json:"tcp_optimization"`
	BufferBloatControl    bool    `json:"buffer_bloat_control"`
	AdaptiveRouting       bool    `json:"adaptive_routing"`
	AutoTuning           bool    `json:"auto_tuning"`
}

// TrafficOptimizer оптимизирует трафик для игр
type TrafficOptimizer struct {
	config       GamingConfig
	stats        GamingStats
	patterns     TrafficPatterns
	isOptimizing bool
}

// QoSController управляет качеством обслуживания
type QoSController struct {
	rules        []QoSRule
	priorities   map[string]int
	isActive     bool
}

// LatencyMonitor отслеживает задержки
type LatencyMonitor struct {
	measurements []LatencyMeasurement
	thresholds   LatencyThresholds
	alerts       []LatencyAlert
}

// NewGamingMode создает новый игровой режим
func NewGamingMode(manager *Manager) *GamingMode {
	logger := utils.NewLogger("gaming")

	config := GamingConfig{
		Enabled:               true,
		MaxLatency:           100,    // ms
		MaxJitter:            50,     // ms
		MaxPacketLoss:        1.0,    // %
		TrafficShaping:       true,
		PacketPrioritization: true,
		UDPOptimization:      true,
		TCPOptimization:      true,
		BufferBloatControl:   true,
		AdaptiveRouting:      true,
		AutoTuning:          true,
	}

	return &GamingMode{
		manager:   manager,
		isEnabled: false,
		config:    config,
		optimizer: NewTrafficOptimizer(config),
		qos:       NewQoSController(),
		monitor:   NewLatencyMonitor(),
		logger:    logger,
	}
}

// Start запускает игровой режим
func (gm *GamingMode) Start() error {
	if gm.isEnabled {
		return fmt.Errorf("gaming mode is already enabled")
	}

	gm.isEnabled = true
	gm.logger.Info("Starting gaming mode")

	// Включение оптимизатора
	if err := gm.optimizer.Start(); err != nil {
		return fmt.Errorf("failed to start optimizer: %v", err)
	}

	// Включение QoS
	if err := gm.qos.Start(); err != nil {
		return fmt.Errorf("failed to start QoS: %v", err)
	}

	// Включение монитора задержек
	if err := gm.monitor.Start(); err != nil {
		return fmt.Errorf("failed to start latency monitor: %v", err)
	}

	// Настройка системы для игр
	if err := gm.configureSystem(); err != nil {
		return fmt.Errorf("failed to configure system: %v", err)
	}

	// Запуск мониторинга производительности
	go gm.monitoringLoop()

	gm.logger.Info("Gaming mode started successfully")
	return nil
}

// Stop останавливает игровой режим
func (gm *GamingMode) Stop() error {
	if !gm.isEnabled {
		return nil
	}

	gm.isEnabled = false
	gm.logger.Info("Stopping gaming mode")

	// Остановка компонентов
	gm.optimizer.Stop()
	gm.qos.Stop()
	gm.monitor.Stop()

	// Восстановление настроек системы
	if err := gm.restoreSystem(); err != nil {
		gm.logger.Error("Failed to restore system settings", "error", err)
	}

	gm.logger.Info("Gaming mode stopped")
	return nil
}

// Enable включает игровой режим
func (gm *GamingMode) Enable() {
	if !gm.isEnabled {
		gm.Start()
	}
}

// Disable выключает игровой режим
func (gm *GamingMode) Disable() {
	if gm.isEnabled {
		gm.Stop()
	}
}

// OptimizeBasedOnPatterns оптимизирует на основе паттернов трафика
func (gm *GamingMode) OptimizeBasedOnPatterns(patterns TrafficPatterns) {
	if !gm.isEnabled {
		return
	}

	gm.optimizer.UpdatePatterns(patterns)
	
	// Применение оптимизаций
	if err := gm.applyOptimizations(); err != nil {
		gm.logger.Error("Failed to apply optimizations", "error", err)
	}
}

// UpdateConfig обновляет конфигурацию
func (gm *GamingMode) UpdateConfig(config GamingConfig) error {
	gm.config = config
	gm.optimizer.UpdateConfig(config)
	
	// Применение новой конфигурации
	if gm.isEnabled {
		return gm.configureSystem()
	}
	
	return nil
}

// GetStats возвращает статистику игрового режима
func (gm *GamingMode) GetStats() GamingStats {
	return gm.optimizer.GetStats()
}

// GetRecommendations возвращает рекомендации по оптимизации
func (gm *GamingMode) GetRecommendations() []OptimizationRecommendation {
	return gm.optimizer.GetRecommendations()
}

// Внутренние методы

func (gm *GamingMode) configureSystem() error {
	gm.logger.Info("Configuring system for gaming")

	// 1. Настройка TCP параметров для снижения задержки
	if err := gm.configureTCP(); err != nil {
		return fmt.Errorf("failed to configure TCP: %v", err)
	}

	// 2. Настройка UDP параметров
	if err := gm.configureUDP(); err != nil {
		return fmt.Errorf("failed to configure UDP: %v", err)
	}

	// 3. Настройка сетевых интерфейсов
	if err := gm.configureNetworkInterfaces(); err != nil {
		return fmt.Errorf("failed to configure network interfaces: %v", err)
	}

	// 4. Настройка QoS
	if err := gm.configureQoS(); err != nil {
		return fmt.Errorf("failed to configure QoS: %v", err)
	}

	// 5. Настройка планировщика пакетов
	if err := gm.configurePacketScheduler(); err != nil {
		return fmt.Errorf("failed to configure packet scheduler: %v", err)
	}

	gm.logger.Info("System configured for gaming")
	return nil
}

func (gm *GamingMode) configureTCP() error {
	// Оптимизация TCP для игр
	tcpConfigs := []string{
		// Уменьшение задержки
		"net.ipv4.tcp_slow_start_after_idle=0",
		"net.ipv4.tcp_low_latency=1",
		"net.ipv4.tcp_timestamps=1",
		"net.ipv4.tcp_sack=1",
		
		// Быстрая передача данных
		"net.ipv4.tcp_window_scaling=1",
		"net.ipv4.tcp_adv_win_scale=1",
		"net.ipv4.tcp_moderate_rcvbuf=1",
		
		// Быстрое восстановление
		"net.ipv4.tcp_frto=2",
		"net.ipv4.tcp_frto_response=2",
		
		// Управление перегрузками
		"net.ipv4.tcp_congestion_control=bbr",
		"net.ipv4.tcp_notsent_lowat=16384",
		
		// Keepalive
		"net.ipv4.tcp_keepalive_time=60",
		"net.ipv4.tcp_keepalive_intvl=10",
		"net.ipv4.tcp_keepalive_probes=6",
		
		// Передачи
		"net.ipv4.tcp_syn_retries=3",
		"net.ipv4.tcp_synack_retries=3",
		"net.ipv4.tcp_retries2=5",
	}

	// Применение TCP настроек
	for _, config := range tcpConfigs {
		if err := applySysctl(config); err != nil {
			gm.logger.Warn("Failed to apply TCP config", "config", config, "error", err)
		}
	}

	return nil
}

func (gm *GamingMode) configureUDP() error {
	// Оптимизация UDP для игр
	udpConfigs := []string{
		// Размеры буферов
		"net.core.rmem_max=134217728",
		"net.core.wmem_max=134217728",
		"net.core.rmem_default=16777216",
		"net.core.wmem_default=16777216",
		
		// Максимальное количество сокетов
		"net.core.somaxconn=4096",
		"net.core.netdev_max_backlog=10000",
		
		// Очереди
		"net.ipv4.udp_mem=16777216 25165824 33554432",
		
		// Размеры буферов UDP
		"net.ipv4.udp_rmem_min=4096",
		"net.ipv4.udp_wmem_min=4096",
	}

	// Применение UDP настроек
	for _, config := range udpConfigs {
		if err := applySysctl(config); err != nil {
			gm.logger.Warn("Failed to apply UDP config", "config", config, "error", err)
		}
	}

	return nil
}

func (gm *GamingMode) configureNetworkInterfaces() error {
	// Настройка сетевых интерфейсов для снижения задержки
	interfaceConfigs := []string{
		// Отключение автосогласования (если возможно)
		"ethtool -s eth0 speed 1000 duplex full autoneg off",
		
		// Настройка прерываний
		"ethtool -C eth0 rx-usecs 8 tx-usecs 8",
		
		// Включение аппаратного ускорения
		"ethtool -K eth0 tso on gso on gro on",
		
		// Настройка очередей
		"ethtool -L eth0 combined 8",
		
		// Увеличение размера буферов
		"ethtool -G eth0 rx 4096 tx 4096",
	}

	// Применение настроек интерфейсов
	for _, config := range interfaceConfigs {
		if err := exec.Command("sh", "-c", config).Run(); err != nil {
			gm.logger.Warn("Failed to configure interface", "config", config, "error", err)
		}
	}

	return nil
}

func (gm *GamingMode) configureQoS() error {
	// Настройка Quality of Service для игрового трафика
	
	qosRules := []QoSRule{
		{
			Priority:    1,
			Protocol:    "udp",
			PortRange:   "27000-28000", // Steam/игровые порты
			DSCP:        46,            // Expedited Forwarding
			RateLimit:   "1000mbit",
			Burst:       "10mbit",
		},
		{
			Priority:    2,
			Protocol:    "tcp",
			PortRange:   "27000-28000",
			DSCP:        34,            // Assured Forwarding
			RateLimit:   "500mbit",
			Burst:       "5mbit",
		},
		{
			Priority:    3,
			Protocol:    "udp",
			PortRange:   "3478-3479",   // STUN
			DSCP:        46,
			RateLimit:   "100mbit",
			Burst:       "2mbit",
		},
		{
			Priority:    4,
			Protocol:    "udp",
			Port:        51820,         // WireGuard
			DSCP:        46,
			RateLimit:   "unlimited",
		},
	}

	// Применение правил QoS
	for _, rule := range qosRules {
		if err := gm.qos.AddRule(rule); err != nil {
			gm.logger.Warn("Failed to add QoS rule", "rule", rule, "error", err)
		}
	}

	return nil
}

func (gm *GamingMode) configurePacketScheduler() error {
	// Настройка планировщика пакетов для снижения задержки
	
	schedulerConfigs := []string{
		// Установка планировщика FQ_CODEL для снижения bufferbloat
		"tc qdisc add dev eth0 root fq_codel limit 10240 flows 1024 quantum 1514 target 5ms interval 100ms noecn",
		
		// Настройка fair queueing
		"tc qdisc add dev eth0 parent 1: fq_codel quantum 300 limit 10240 flows 1024 target 5ms interval 100ms",
		
		// Ограничение полосы (если нужно)
		// "tc qdisc add dev eth0 root tbf rate 1000mbit burst 32kbit latency 20ms",
	}

	// Применение настроек планировщика
	for _, config := range schedulerConfigs {
		if err := exec.Command("sh", "-c", config).Run(); err != nil {
			gm.logger.Warn("Failed to configure packet scheduler", "config", config, "error", err)
		}
	}

	return nil
}

func (gm *GamingMode) restoreSystem() error {
	gm.logger.Info("Restoring system settings")

	// Восстановление TCP настроек
	defaultTCPConfigs := []string{
		"net.ipv4.tcp_slow_start_after_idle=1",
		"net.ipv4.tcp_low_latency=0",
		"net.ipv4.tcp_congestion_control=cubic",
	}

	// Восстановление UDP настроек
	defaultUDPConfigs := []string{
		"net.core.rmem_max=212992",
		"net.core.wmem_max=212992",
		"net.core.rmem_default=212992",
		"net.core.wmem_default=212992",
	}

	// Применение настроек по умолчанию
	for _, config := range append(defaultTCPConfigs, defaultUDPConfigs...) {
		applySysctl(config)
	}

	// Очистка правил QoS
	gm.qos.ClearRules()

	// Очистка планировщика пакетов
	exec.Command("sh", "-c", "tc qdisc del dev eth0 root").Run()

	gm.logger.Info("System settings restored")
	return nil
}

func (gm *GamingMode) applyOptimizations() error {
	// Применение оптимизаций на основе текущих паттернов
	
	optimizations := gm.optimizer.GetOptimizations()
	
	for _, opt := range optimizations {
		switch opt.Type {
		case "tcp_tuning":
			gm.applyTCPTuning(opt.Params)
		case "udp_tuning":
			gm.applyUDPTuning(opt.Params)
		case "buffer_adjustment":
			gm.adjustBuffers(opt.Params)
		case "qos_adjustment":
			gm.adjustQoS(opt.Params)
		case "route_optimization":
			gm.optimizeRoutes(opt.Params)
		}
	}

	return nil
}

func (gm *GamingMode) applyTCPTuning(params map[string]interface{}) {
	// Настройка TCP параметров на основе рекомендаций
	if windowSize, ok := params["window_size"].(int); ok {
		sysctl := fmt.Sprintf("net.ipv4.tcp_rmem=%d %d %d", 
			windowSize/2, windowSize, windowSize*2)
		applySysctl(sysctl)
	}
	
	if keepalive, ok := params["keepalive"].(bool); ok && keepalive {
		applySysctl("net.ipv4.tcp_keepalive_time=30")
		applySysctl("net.ipv4.tcp_keepalive_intvl=5")
	}
}

func (gm *GamingMode) applyUDPTuning(params map[string]interface{}) {
	// Настройка UDP параметров
	if bufferSize, ok := params["buffer_size"].(int); ok {
		sysctl := fmt.Sprintf("net.core.rmem_max=%d", bufferSize)
		applySysctl(sysctl)
		applySysctl(fmt.Sprintf("net.core.wmem_max=%d", bufferSize))
	}
}

func (gm *GamingMode) adjustBuffers(params map[string]interface{}) {
	// Регулировка размеров буферов
	if rxBuffer, ok := params["rx_buffer"].(int); ok {
		cmd := fmt.Sprintf("ethtool -G eth0 rx %d", rxBuffer)
		exec.Command("sh", "-c", cmd).Run()
	}
	
	if txBuffer, ok := params["tx_buffer"].(int); ok {
		cmd := fmt.Sprintf("ethtool -G eth0 tx %d", txBuffer)
		exec.Command("sh", "-c", cmd).Run()
	}
}

func (gm *GamingMode) adjustQoS(params map[string]interface{}) {
	// Регулировка QoS
	if priority, ok := params["priority"].(int); ok {
		// Обновление приоритетов на основе текущей нагрузки
		gm.qos.UpdatePriorities(map[string]int{
			"gaming": priority,
			"streaming": priority - 1,
			"default": priority - 2,
		})
	}
}

func (gm *GamingMode) optimizeRoutes(params map[string]interface{}) {
	// Оптимизация маршрутов
	if gateway, ok := params["gateway"].(string); ok {
		// Добавление маршрута через оптимальный шлюз
		cmd := fmt.Sprintf("ip route add default via %s metric 100", gateway)
		exec.Command("sh", "-c", cmd).Run()
	}
}

func (gm *GamingMode) monitoringLoop() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	reportTicker := time.NewTicker(60 * time.Second)
	defer reportTicker.Stop()

	for {
		select {
		case <-gm.manager.ctx.Done():
			return
		case <-ticker.C:
			gm.checkPerformance()
		case <-reportTicker.C:
			gm.generateReport()
		}
	}
}

func (gm *GamingMode) checkPerformance() {
	// Проверка производительности сети
	stats := gm.manager.GetStats()
	
	// Проверка задержки
	if stats.AverageLatency > time.Duration(gm.config.MaxLatency)*time.Millisecond {
		gm.logger.Warn("High latency detected", 
			"latency", stats.AverageLatency, 
			"threshold", gm.config.MaxLatency)
		
		// Активация дополнительных оптимизаций
		gm.optimizer.ActivateHighLatencyMode()
	}

	// Проверка потерь пакетов
	if stats.PacketLoss > gm.config.MaxPacketLoss {
		gm.logger.Warn("High packet loss detected",
			"loss", stats.PacketLoss,
			"threshold", gm.config.MaxPacketLoss)
		
		// Коррекция параметров
		gm.optimizer.AdjustForPacketLoss()
	}

	// Проверка джиттера
	if stats.AverageJitter > time.Duration(gm.config.MaxJitter)*time.Millisecond {
		gm.logger.Warn("High jitter detected",
			"jitter", stats.AverageJitter,
			"threshold", gm.config.MaxJitter)
	}
}

func (gm *GamingMode) generateReport() {
	// Генерация отчета о производительности
	stats := gm.optimizer.GetStats()
	recommendations := gm.optimizer.GetRecommendations()

	report := GamingReport{
		Timestamp:      time.Now(),
		Stats:          stats,
		Recommendations: recommendations,
		Config:         gm.config,
		Status:         "optimal",
	}

	// Проверка статуса
	if stats.AverageLatency > time.Duration(gm.config.MaxLatency)*time.Millisecond {
		report.Status = "high_latency"
	} else if stats.PacketLoss > gm.config.MaxPacketLoss {
		report.Status = "high_packet_loss"
	} else if stats.AverageJitter > time.Duration(gm.config.MaxJitter)*time.Millisecond {
		report.Status = "high_jitter"
	}

	// Сохранение отчета
	gm.manager.db.SaveGamingReport(report)
	
	// Отправка уведомления при проблемах
	if report.Status != "optimal" {
		gm.sendAlert(report)
	}
}

func (gm *GamingMode) sendAlert(report GamingReport) {
	// Отправка уведомления о проблемах с производительностью
	alert := LatencyAlert{
		Timestamp:   time.Now(),
		Type:        "performance_issue",
		Severity:    "warning",
		Message:     fmt.Sprintf("Gaming performance issue: %s", report.Status),
		Details:     report,
	}

	gm.monitor.AddAlert(alert)
	gm.manager.broadcastEvent(Event{
		Type:      "gaming_alert",
		Data:      alert,
		Timestamp: time.Now(),
	})
}

// Вспомогательные функции и структуры

func applySysctl(config string) error {
	parts := strings.Split(config, "=")
	if len(parts) != 2 {
		return fmt.Errorf("invalid sysctl config: %s", config)
	}
	
	file := "/proc/sys/" + strings.ReplaceAll(parts[0], ".", "/")
	return os.WriteFile(file, []byte(parts[1]), 0644)
}

type QoSRule struct {
	Priority   int
	Protocol   string
	Port       int
	PortRange  string
	DSCP       int
	RateLimit  string
	Burst      string
	Interface  string
}

type TrafficPatterns struct {
	UDPTraffic     float64
	TCPTraffic     float64
	AveragePacketSize int
	TrafficSpikes  []TrafficSpike
	TimeOfDay      map[int]float64 // час -> нагрузка
}

type GamingStats struct {
	AverageLatency  time.Duration
	MaxLatency      time.Duration
	MinLatency      time.Duration
	AverageJitter   time.Duration
	PacketLoss      float64
	ThroughputUp    uint64
	ThroughputDown  uint64
	UDPPackets      uint64
	TCPPackets      uint64
	Retransmissions uint64
	BufferUsage     float64
}

type OptimizationRecommendation struct {
	Type        string
	Priority    string
	Description string
	Action      string
	ExpectedGain string
}

type GamingReport struct {
	Timestamp      time.Time
	Stats          GamingStats
	Recommendations []OptimizationRecommendation
	Config         GamingConfig
	Status         string
}

type LatencyMeasurement struct {
	Timestamp time.Time
	PeerID    string
	Latency   time.Duration
	Jitter    time.Duration
}

type LatencyThresholds struct {
	Warning  time.Duration
	Critical time.Duration
}

type LatencyAlert struct {
	Timestamp time.Time
	Type      string
	Severity  string
	Message   string
	Details   interface{}
}
