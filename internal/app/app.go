package app

import (
	"context"
	"fmt"
	"sync"
	"time"

	"supressor/internal/api"
	"supressor/internal/auth"
	"supressor/internal/config"
	"supressor/internal/network"
	"supressor/internal/storage"
	"supressor/internal/utils"
)

// App представляет основное приложение
type App struct {
	ctx        context.Context
	cancel     context.CancelFunc
	config     *config.Config
	profile    *config.Profile
	networkMgr *network.Manager
	apiServer  *api.Server
	authMgr    *auth.Manager
	db         *storage.Database
	logger     *utils.Logger
	mu         sync.RWMutex
	startTime  time.Time
	status     Status
}

// Status представляет статус приложения
type Status struct {
	Connected   bool      `json:"connected"`
	NetworkName string    `json:"network_name"`
	PeerCount   int       `json:"peer_count"`
	TxBytes     uint64    `json:"tx_bytes"`
	RxBytes     uint64    `json:"rx_bytes"`
	Uptime      string    `json:"uptime"`
	Version     string    `json:"version"`
	LastUpdate  time.Time `json:"last_update"`
}

// New создает новое приложение
func New(ctx context.Context, cfg *config.Config, profileName string) (*App, error) {
	ctx, cancel := context.WithCancel(ctx)

	logger := utils.NewLogger("app")

	// Загрузка профиля
	profile, err := config.LoadProfile(profileName)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to load profile: %v", err)
	}

	// Инициализация базы данных
	db, err := storage.New(cfg.Database.Path)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to init database: %v", err)
	}

	// Создание сетевого менеджера
	networkMgr, err := network.NewManager(ctx, cfg, profile)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to create network manager: %v", err)
	}

	// Создание менеджера аутентификации
	authMgr := auth.NewManager(cfg, db)

	// Создание API сервера
	apiServer := api.NewServer(cfg, networkMgr, authMgr)

	return &App{
		ctx:        ctx,
		cancel:     cancel,
		config:     cfg,
		profile:    profile,
		networkMgr: networkMgr,
		apiServer:  apiServer,
		authMgr:    authMgr,
		db:         db,
		logger:     logger,
		startTime:  time.Now(),
		status: Status{
			Version:    "1.0.0",
			LastUpdate: time.Now(),
		},
	}, nil
}

// Init инициализирует приложение
func (a *App) Init() error {
	a.logger.Info("Initializing application")

	// Инициализация базы данных
	if err := a.db.Init(); err != nil {
		return fmt.Errorf("failed to init database: %v", err)
	}

	// Инициализация сетевого менеджера
	if err := a.networkMgr.Init(); err != nil {
		return fmt.Errorf("failed to init network manager: %v", err)
	}

	// Инициализация API сервера
	if err := a.apiServer.Init(); err != nil {
		return fmt.Errorf("failed to init API server: %v", err)
	}

	a.logger.Info("Application initialized successfully")
	return nil
}

// Start запускает приложение
func (a *App) Start() error {
	a.logger.Info("Starting application")

	// Запуск сетевого менеджера
	if err := a.networkMgr.Start(); err != nil {
		return fmt.Errorf("failed to start network manager: %v", err)
	}

	// Запуск API сервера
	go func() {
		if err := a.apiServer.Start(); err != nil {
			a.logger.Error("API server failed", "error", err)
		}
	}()

	// Запуск фоновых задач
	go a.backgroundTasks()

	a.logger.Info("Application started successfully")
	return nil
}

// Stop останавливает приложение
func (a *App) Stop() error {
	a.logger.Info("Stopping application")

	// Остановка сетевого менеджера
	if err := a.networkMgr.Stop(); err != nil {
		a.logger.Error("Failed to stop network manager", "error", err)
	}

	// Остановка API сервера
	if err := a.apiServer.Stop(); err != nil {
		a.logger.Error("Failed to stop API server", "error", err)
	}

	// Закрытие базы данных
	if err := a.db.Close(); err != nil {
		a.logger.Error("Failed to close database", "error", err)
	}

	a.cancel()
	a.logger.Info("Application stopped")
	return nil
}

// GetStatus возвращает текущий статус приложения
func (a *App) GetStatus() Status {
	a.mu.RLock()
	defer a.mu.RUnlock()

	status := a.networkMgr.GetStatus()
	a.status.Connected = status.Connected
	a.status.NetworkName = status.NetworkName
	a.status.PeerCount = status.PeerCount
	a.status.TxBytes = status.TxBytes
	a.status.RxBytes = status.RxBytes
	a.status.Uptime = formatDuration(time.Since(a.startTime))
	a.status.LastUpdate = time.Now()

	return a.status
}

// GetNetworkManager возвращает сетевой менеджер
func (a *App) GetNetworkManager() *network.Manager {
	return a.networkMgr
}

// GetAuthManager возвращает менеджер аутентификации
func (a *App) GetAuthManager() *auth.Manager {
	return a.authMgr
}

// GetAPIServer возвращает API сервер
func (a *App) GetAPIServer() *api.Server {
	return a.apiServer
}

// CreateNetwork создает новую сеть
func (a *App) CreateNetwork(name, password string) (string, error) {
	networkID, err := a.networkMgr.CreateNetwork(name, password)
	if err != nil {
		return "", err
	}

	// Сохраняем информацию о сети в профиле
	a.profile.Networks = append(a.profile.Networks, config.NetworkInfo{
		ID:   networkID,
		Name: name,
		Role: "owner",
	})

	if err := config.SaveProfile(a.profile); err != nil {
		a.logger.Error("Failed to save profile", "error", err)
	}

	return networkID, nil
}

// JoinNetwork присоединяется к существующей сети
func (a *App) JoinNetwork(networkID, password string) error {
	if err := a.networkMgr.JoinNetwork(networkID, password); err != nil {
		return err
	}

	// Получаем информацию о сети
	networkInfo, err := a.networkMgr.GetNetworkInfo(networkID)
	if err != nil {
		return err
	}

	// Сохраняем информацию о сети в профиле
	a.profile.Networks = append(a.profile.Networks, config.NetworkInfo{
		ID:   networkID,
		Name: networkInfo.Name,
		Role: "member",
	})

	if err := config.SaveProfile(a.profile); err != nil {
		a.logger.Error("Failed to save profile", "error", err)
	}

	return nil
}

// LeaveNetwork покидает сеть
func (a *App) LeaveNetwork(networkID string) error {
	if err := a.networkMgr.LeaveNetwork(networkID); err != nil {
		return err
	}

	// Удаляем сеть из профиля
	for i, net := range a.profile.Networks {
		if net.ID == networkID {
			a.profile.Networks = append(a.profile.Networks[:i], a.profile.Networks[i+1:]...)
			break
		}
	}

	if err := config.SaveProfile(a.profile); err != nil {
		a.logger.Error("Failed to save profile", "error", err)
	}

	return nil
}

// ListNetworks возвращает список сетей
func (a *App) ListNetworks() ([]config.NetworkInfo, error) {
	return a.profile.Networks, nil
}

// Фоновые задачи
func (a *App) backgroundTasks() {
	// Таймер для обновления статуса
	statusTicker := time.NewTicker(5 * time.Second)
	defer statusTicker.Stop()

	// Таймер для сохранения состояния
	saveTicker := time.NewTicker(30 * time.Second)
	defer saveTicker.Stop()

	// Таймер для проверки здоровья
	healthTicker := time.NewTicker(60 * time.Second)
	defer healthTicker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return

		case <-statusTicker.C:
			a.updateStatus()

		case <-saveTicker.C:
			a.saveState()

		case <-healthTicker.C:
			a.healthCheck()
		}
	}
}

func (a *App) updateStatus() {
	a.mu.Lock()
	defer a.mu.Unlock()

	status := a.networkMgr.GetStatus()
	a.status.Connected = status.Connected
	a.status.NetworkName = status.NetworkName
	a.status.PeerCount = status.PeerCount
	a.status.TxBytes = status.TxBytes
	a.status.RxBytes = status.RxBytes
}

func (a *App) saveState() {
	// Сохраняем профиль
	if err := config.SaveProfile(a.profile); err != nil {
		a.logger.Error("Failed to save profile", "error", err)
	}

	// Сохраняем состояние сети
	if err := a.networkMgr.SaveState(); err != nil {
		a.logger.Error("Failed to save network state", "error", err)
	}
}

func (a *App) healthCheck() {
	// Проверка состояния сети
	if err := a.networkMgr.HealthCheck(); err != nil {
		a.logger.Error("Network health check failed", "error", err)
	}

	// Проверка состояния базы данных
	if err := a.db.HealthCheck(); err != nil {
		a.logger.Error("Database health check failed", "error", err)
	}

	// Проверка доступности API
	if err := a.apiServer.HealthCheck(); err != nil {
		a.logger.Error("API health check failed", "error", err)
	}
}

// Вспомогательная функция
func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
