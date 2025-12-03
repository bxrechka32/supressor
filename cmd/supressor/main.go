package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/uuid"

	"supressor/internal/api"
	"supressor/internal/auth"
	"supressor/internal/config"
	"supressor/internal/network"
	"supressor/internal/storage"
	"supressor/internal/ui"
	"supressor/internal/utils"
)

// Глобальные стили
var (
	rainbow = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF0000")).
		Bold(true).
		Blink(true)

	gradientStyle = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF6B9D")).
		Background(lipgloss.Color("#0A0A0A")).
		Padding(0, 2)

	statusOnline = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FF00")).
		Background(lipgloss.Color("#003300")).
		Padding(0, 1).
		Bold(true)

	statusOffline = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FF3333")).
		Background(lipgloss.Color("#330000")).
		Padding(0, 1)

	highlight = lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFF00")).
		Background(lipgloss.Color("#444400")).
		Bold(true)
)

// MainModel - основная модель приложения
type MainModel struct {
	ctx          context.Context
	cancel       context.CancelFunc
	currentView  string
	views        map[string]tea.Model
	width        int
	height       int
	profile      *config.Profile
	networkMgr   *network.Manager
	configMgr    *config.Manager
	db           *storage.Database
	apiServer    *api.Server
	aiAssistant  *ai.Assistant
	isConnected  bool
	showHelp     bool
	notifications []ui.Notification
	theme        ui.Theme
	keyMap       ui.KeyMap
	animations   ui.AnimationManager
}

// Инициализация приложения
func NewMainModel() (*MainModel, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Инициализация логгера
	logger := utils.NewLogger("supressor")
	logger.Info("Запуск Supressor v1.0.0")

	// Загрузка конфигурации
	configMgr, err := config.NewManager()
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки конфигурации: %v", err)
	}

	// Инициализация БД
	db, err := storage.NewDatabase()
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации БД: %v", err)
	}

	// Загрузка или создание профиля
	profile, err := configMgr.LoadOrCreateProfile()
	if err != nil {
		return nil, fmt.Errorf("ошибка загрузки профиля: %v", err)
	}

	// Инициализация сетевого менеджера
	networkMgr, err := network.NewManager(ctx, profile)
	if err != nil {
		return nil, fmt.Errorf("ошибка инициализации сети: %v", err)
	}

	// Инициализация AI ассистента
	aiAssistant := ai.NewAssistant(profile, networkMgr)

	// Создание API сервера
	apiServer := api.NewServer(networkMgr, configMgr, profile)

	// Загрузка темы
	theme := ui.LoadTheme(profile.Settings.Theme)

	model := &MainModel{
		ctx:         ctx,
		cancel:      cancel,
		currentView: "main",
		views:       make(map[string]tea.Model),
		profile:     profile,
		networkMgr:  networkMgr,
		configMgr:   configMgr,
		db:          db,
		apiServer:   apiServer,
		aiAssistant: aiAssistant,
		theme:       theme,
		keyMap:      ui.DefaultKeyMap(),
		animations:  ui.NewAnimationManager(),
	}

	// Инициализация представлений
	model.initViews()

	return model, nil
}

func (m *MainModel) initViews() {
	m.views["main"] = ui.NewMainView(m.profile, m.networkMgr)
	m.views["network"] = ui.NewNetworkView(m.networkMgr)
	m.views["peers"] = ui.NewPeerListView(m.networkMgr)
	m.views["settings"] = ui.NewSettingsView(m.profile, m.configMgr)
	m.views["stats"] = ui.NewStatsView(m.networkMgr)
	m.views["create"] = ui.NewCreateNetworkView(m.configMgr)
	m.views["gaming"] = ui.NewGamingView(m.networkMgr)
}

// Запуск фоновых процессов
func (m *MainModel) startBackgroundTasks() {
	// Запуск сетевого мониторинга
	go m.networkMgr.StartMonitoring()

	// Запуск API сервера
	go func() {
		if err := m.apiServer.Start(); err != nil {
			m.addNotification(ui.Notification{
				Type:    ui.NotifyError,
				Message: fmt.Sprintf("API сервер: %v", err),
			})
		}
	}()

	// Запуск AI ассистента
	go m.aiAssistant.Start()

	// Обновление статистики
	go m.updateStatsLoop()

	// Проверка обновлений
	go m.checkForUpdates()
}

func (m *MainModel) updateStatsLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return
		case <-ticker.C:
			// Обновление статистики сети
			stats := m.networkMgr.GetStats()
			
			// Проверка аномалий через AI
			if anomaly := m.aiAssistant.CheckTrafficAnomaly(stats); anomaly != nil {
				m.addNotification(ui.Notification{
					Type:    ui.NotifyWarning,
					Message: anomaly.Message,
					Data:    anomaly.Data,
				})
			}

			// Отправка команды обновления в TUI
			// (реализация через чанелы в реальном приложении)
		}
	}
}

// Обработка команд TUI
func (m *MainModel) Init() tea.Cmd {
	m.startBackgroundTasks()
	
	return tea.Batch(
		tea.EnterAltScreen,
		m.animations.Init(),
		ui.ShowWelcomeAnimation(),
		m.checkInitialConnection(),
	)
}

func (m *MainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		// Обновляем размеры всех view
		for _, view := range m.views {
			if updater, ok := view.(interface{ SetSize(int, int) }); ok {
				updater.SetSize(msg.Width, msg.Height)
			}
		}
		
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			if m.currentView == "main" {
				return m, tea.Quit
			}
		case "?":
			m.showHelp = !m.showHelp
		case "f1":
			m.showHelp = true
		case "tab":
			m.cycleView()
		case "ctrl+p":
			m.switchProfile()
		case "ctrl+g":
			m.toggleGamingMode()
		case "ctrl+a":
			m.toggleAIAssistant()
		case "ctrl+s":
			m.showSecurityScan()
		}

	case ui.NotificationMsg:
		m.addNotification(msg.Notification)
		
	case ui.ViewChangeMsg:
		m.currentView = msg.View
		
	case network.ConnectionEvent:
		m.handleConnectionEvent(msg)
		
	case ai.RecommendationMsg:
		m.handleAIRecommendation(msg)
	}

	// Обновляем текущее view
	if view, ok := m.views[m.currentView]; ok {
		updatedView, cmd := view.Update(msg)
		m.views[m.currentView] = updatedView
		if cmd != nil {
			cmds = append(cmds, cmd)
		}
	}

	// Обновление анимаций
	animCmd := m.animations.Update(msg)
	if animCmd != nil {
		cmds = append(cmds, animCmd)
	}

	return m, tea.Batch(cmds...)
}

func (m *MainModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Инициализация..."
	}

	// Верхняя панель с информацией
	header := m.renderHeader()

	// Основное содержимое
	var content string
	if view, ok := m.views[m.currentView]; ok {
		content = view.View()
	}

	// Нижняя панель с подсказками
	footer := m.renderFooter()

	// Уведомления
	notifications := m.renderNotifications()

	// Собираем все вместе
	return lipgloss.JoinVertical(
		lipgloss.Left,
		header,
		content,
		notifications,
		footer,
	)
}

func (m *MainModel) renderHeader() string {
	networkStatus := "🔴 ОФФЛАЙН"
	if m.isConnected {
		networkStatus = "🟢 ОНЛАЙН"
	}

	profileInfo := fmt.Sprintf("👤 %s", m.profile.DisplayName)
	if m.profile.NetworkName != "" {
		profileInfo += fmt.Sprintf(" | 🌐 %s", m.profile.NetworkName)
	}

	stats := m.networkMgr.GetStats()
	trafficInfo := fmt.Sprintf("⬆ %s ⬇ %s",
		utils.FormatBytes(stats.TotalTxBytes),
		utils.FormatBytes(stats.TotalRxBytes),
	)

	aiStatus := "🤖 ВКЛ"
	if !m.aiAssistant.IsActive() {
		aiStatus = "🤖 ВЫКЛ"
	}

	return lipgloss.JoinHorizontal(
		lipgloss.Top,
		gradientStyle.Render("SUPRESSOR v1.0"),
		" | ",
		profileInfo,
		" | ",
		networkStatus,
		" | ",
		trafficInfo,
		" | ",
		aiStatus,
		" | ",
		fmt.Sprintf("👥 %d", len(m.networkMgr.GetPeers())),
	)
}

func (m *MainModel) renderFooter() string {
	helpText := ""
	if m.showHelp {
		helpText = m.renderHelp()
	} else {
		helpText = m.keyMap.Help()
	}

	return lipgloss.NewStyle().
		Foreground(lipgloss.Color("#888")).
		BorderTop(true).
		BorderStyle(lipgloss.ThickBorder()).
		BorderForeground(lipgloss.Color("#555")).
		Padding(0, 1).
		Render(helpText)
}

func (m *MainModel) renderNotifications() string {
	if len(m.notifications) == 0 {
		return ""
	}

	var notifs []string
	for _, n := range m.notifications {
		style := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			Padding(0, 1).
			MarginBottom(1)

		switch n.Type {
		case ui.NotifySuccess:
			style = style.
				Foreground(lipgloss.Color("#00FF00")).
				BorderForeground(lipgloss.Color("#00AA00"))
		case ui.NotifyWarning:
			style = style.
				Foreground(lipgloss.Color("#FFFF00")).
				BorderForeground(lipgloss.Color("#AAAA00"))
		case ui.NotifyError:
			style = style.
				Foreground(lipgloss.Color("#FF0000")).
				BorderForeground(lipgloss.Color("#AA0000"))
		case ui.NotifyInfo:
			style = style.
				Foreground(lipgloss.Color("#00FFFF")).
				BorderForeground(lipgloss.Color("#00AAAA"))
		}

		notifs = append(notifs, style.Render(n.Message))
	}

	return lipgloss.JoinVertical(lipgloss.Left, notifs...)
}

// Обработка событий
func (m *MainModel) handleConnectionEvent(event network.ConnectionEvent) {
	switch event.Type {
	case network.Connected:
		m.isConnected = true
		m.addNotification(ui.Notification{
			Type:    ui.NotifySuccess,
			Message: fmt.Sprintf("Подключено к сети: %s", event.NetworkName),
		})
		
	case network.Disconnected:
		m.isConnected = false
		m.addNotification(ui.Notification{
			Type:    ui.NotifyWarning,
			Message: "Соединение разорвано",
		})
		
	case network.PeerConnected:
		m.addNotification(ui.Notification{
			Type:    ui.NotifyInfo,
			Message: fmt.Sprintf("%s присоединился", event.PeerName),
		})
		
	case network.PeerDisconnected:
		m.addNotification(ui.Notification{
			Type:    ui.NotifyInfo,
			Message: fmt.Sprintf("%s отключился", event.PeerName),
		})
	}
}

func (m *MainModel) handleAIRecommendation(msg ai.RecommendationMsg) {
	m.addNotification(ui.Notification{
		Type:    ui.NotifyInfo,
		Message: msg.Message,
		Data:    msg.Data,
	})
}

func (m *MainModel) addNotification(n ui.Notification) {
	m.notifications = append(m.notifications, n)
	// Ограничиваем количество уведомлений
	if len(m.notifications) > 5 {
		m.notifications = m.notifications[1:]
	}
}

// Завершение работы
func (m *MainModel) cleanup() {
	m.cancel()
	
	if m.networkMgr != nil {
		m.networkMgr.Stop()
	}
	
	if m.apiServer != nil {
		m.apiServer.Stop()
	}
	
	if m.db != nil {
		m.db.Close()
	}
	
	m.configMgr.SaveProfile(m.profile)
}

// Главная функция
func main() {
	// Обработка сигналов
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Инициализация приложения
	model, err := NewMainModel()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Ошибка инициализации: %v\n", err)
		os.Exit(1)
	}
	defer model.cleanup()

	// Запуск TUI
	p := tea.NewProgram(model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
		tea.WithFPS(60),
	)

	// Запуск в отдельной горутине для обработки сигналов
	done := make(chan error, 1)
	go func() {
		_, err := p.Run()
		done <- err
	}()

	// Ожидание завершения
	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintf(os.Stderr, "Ошибка TUI: %v\n", err)
			os.Exit(1)
		}
	case sig := <-sigChan:
		fmt.Printf("\nПолучен сигнал %v, завершение...\n", sig)
		p.Quit()
	}

	fmt.Println("Supressor завершен.")
}
