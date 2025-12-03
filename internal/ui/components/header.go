package components

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"supressor/internal/app"
	"supressor/internal/config"
	"supressor/internal/network"
	"supressor/internal/utils"
)

// Header представляет верхнюю панель приложения
type Header struct {
	width       int
	height      int
	app         *app.App
	profile     *config.Profile
	networkMgr  *network.Manager
	status      app.Status
	lastUpdate  time.Time
	styles      *Styles
	logger      *utils.Logger
	isCollapsed bool
	showDetails bool
}

// Styles определяет стили заголовка
type Styles struct {
	Container      lipgloss.Style
	Title          lipgloss.Style
	Subtitle       lipgloss.Style
	StatusOnline   lipgloss.Style
	StatusOffline  lipgloss.Style
	StatusWarning  lipgloss.Style
	StatusError    lipgloss.Style
	NetworkInfo    lipgloss.Style
	PeerInfo       lipgloss.Style
	TrafficInfo    lipgloss.Style
	LatencyInfo    lipgloss.Style
	SecurityInfo   lipgloss.Style
	TimeInfo       lipgloss.Style
	Button         lipgloss.Style
	ButtonActive   lipgloss.Style
	Notification   lipgloss.Style
	NotificationSuccess lipgloss.Style
	NotificationWarning lipgloss.Style
	NotificationError   lipgloss.Style
}

// NewHeader создает новый заголовок
func NewHeader(app *app.App, width, height int) *Header {
	logger := utils.NewLogger("ui:header")
	
	header := &Header{
		width:      width,
		height:     min(height, 10), // Максимальная высота заголовка
		app:        app,
		profile:    app.GetProfile(),
		networkMgr: app.GetNetworkManager(),
		styles:     NewStyles(),
		logger:     logger,
		showDetails: true,
	}
	
	// Обновление статуса
	header.updateStatus()
	
	return header
}

// NewStyles создает стили заголовка
func NewStyles() *Styles {
	return &Styles{
		Container: lipgloss.NewStyle().
			Width(100).
			Padding(0, 1).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#3C3C3C")).
			Background(lipgloss.Color("#1A1A1A")),
		
		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B9D")).
			Bold(true).
			MarginRight(2),
		
		Subtitle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#58C4DD")).
			Italic(true),
		
		StatusOnline: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Background(lipgloss.Color("#003300")).
			Padding(0, 1).
			Bold(true),
		
		StatusOffline: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF3333")).
			Background(lipgloss.Color("#330000")).
			Padding(0, 1).
			Bold(true),
		
		StatusWarning: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFF00")).
			Background(lipgloss.Color("#333300")).
			Padding(0, 1).
			Bold(true),
		
		StatusError: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Background(lipgloss.Color("#660000")).
			Padding(0, 1).
			Bold(true).
			Blink(true),
		
		NetworkInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FFFF")).
			MarginLeft(1),
		
		PeerInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFA500")).
			MarginLeft(1),
		
		TrafficInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			MarginLeft(1),
		
		LatencyInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF00FF")).
			MarginLeft(1),
		
		SecurityInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF4500")).
			MarginLeft(1),
		
		TimeInfo: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			MarginLeft(1),
		
		Button: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC")).
			Background(lipgloss.Color("#333333")).
			Padding(0, 1).
			MarginLeft(1),
		
		ButtonActive: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5555FF")).
			Padding(0, 1).
			MarginLeft(1).
			Bold(true),
		
		Notification: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#444444")).
			Padding(0, 1).
			MarginLeft(1),
		
		NotificationSuccess: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Background(lipgloss.Color("#004400")).
			Padding(0, 1).
			MarginLeft(1),
		
		NotificationWarning: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFF00")).
			Background(lipgloss.Color("#444400")).
			Padding(0, 1).
			MarginLeft(1),
		
		NotificationError: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF0000")).
			Background(lipgloss.Color("#440000")).
			Padding(0, 1).
			MarginLeft(1),
	}
}

// Init инициализирует заголовок
func (h *Header) Init() tea.Cmd {
	// Запуск обновления статуса каждые 2 секунды
	return tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
		return UpdateStatusMsg{}
	})
}

// Update обновляет состояние заголовка
func (h *Header) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		h.width = msg.Width
		h.height = min(msg.Height, 10)
		
	case UpdateStatusMsg:
		h.updateStatus()
		// Планируем следующее обновление
		return h, tea.Tick(2*time.Second, func(t time.Time) tea.Msg {
			return UpdateStatusMsg{}
		})
		
	case tea.KeyMsg:
		switch msg.String() {
		case "h":
			h.ToggleDetails()
		case "c":
			h.ToggleCollapse()
		case "r":
			h.updateStatus()
			return h, nil
		case "s":
			// Переключение безопасности
			return h, tea.Cmd(func() tea.Msg {
				return ToggleSecurityMsg{}
			})
		case "g":
			// Переключение игрового режима
			return h, tea.Cmd(func() tea.Msg {
				return ToggleGamingModeMsg{}
			})
		}
		
	case NetworkStatusChangedMsg:
		h.updateStatus()
		
	case ProfileUpdatedMsg:
		h.profile = h.app.GetProfile()
		h.updateStatus()
	}
	
	return h, nil
}

// View отображает заголовок
func (h *Header) View() string {
	if h.width <= 0 {
		return ""
	}
	
	var content string
	if h.isCollapsed {
		content = h.renderCollapsed()
	} else if h.showDetails {
		content = h.renderDetailed()
	} else {
		content = h.renderCompact()
	}
	
	// Применяем контейнер
	return h.styles.Container.
		Width(h.width - 2). // Учитываем padding и border
		Render(content)
}

// ToggleDetails переключает отображение деталей
func (h *Header) ToggleDetails() {
	h.showDetails = !h.showDetails
}

// ToggleCollapse переключает свернутое состояние
func (h *Header) ToggleCollapse() {
	h.isCollapsed = !h.isCollapsed
}

// updateStatus обновляет статус
func (h *Header) updateStatus() {
	h.status = h.app.GetStatus()
	h.lastUpdate = time.Now()
}

// renderCollapsed отображает свернутый заголовок
func (h *Header) renderCollapsed() string {
	statusIcon := "🔴"
	statusText := h.styles.StatusOffline.Render("OFFLINE")
	
	if h.status.Connected {
		statusIcon = "🟢"
		statusText = h.styles.StatusOnline.Render("ONLINE")
	}
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		h.styles.Title.Render("SUPRESSOR"),
		statusIcon,
		statusText,
		h.styles.TimeInfo.Render(fmt.Sprintf("🕐 %s", h.lastUpdate.Format("15:04:05"))),
		h.styles.Button.Render("[H] Show"),
	)
}

// renderCompact отображает компактный заголовок
func (h *Header) renderCompact() string {
	// Первая строка: название и статус
	statusLine := h.renderStatusLine()
	
	// Вторая строка: основная информация
	infoLine := h.renderInfoLine()
	
	return lipgloss.JoinVertical(
		lipgloss.Left,
		statusLine,
		infoLine,
	)
}

// renderDetailed отображает подробный заголовок
func (h *Header) renderDetailed() string {
	lines := []string{}
	
	// 1. Статусная строка
	lines = append(lines, h.renderStatusLine())
	
	// 2. Информация о сети
	lines = append(lines, h.renderNetworkLine())
	
	// 3. Информация о пирах
	lines = append(lines, h.renderPeersLine())
	
	// 4. Трафик
	lines = append(lines, h.renderTrafficLine())
	
	// 5. Задержка и потери
	lines = append(lines, h.renderPerformanceLine())
	
	// 6. Время и кнопки
	lines = append(lines, h.renderControlsLine())
	
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

// renderStatusLine отображает строку статуса
func (h *Header) renderStatusLine() string {
	var statusIcon, statusText string
	
	if h.status.Connected {
		statusIcon = "🟢"
		statusText = h.styles.StatusOnline.Render("CONNECTED")
	} else {
		statusIcon = "🔴"
		statusText = h.styles.StatusOffline.Render("DISCONNECTED")
	}
	
	profileInfo := fmt.Sprintf("👤 %s", h.profile.DisplayName)
	if h.profile.Email != "" {
		profileInfo += fmt.Sprintf(" (%s)", h.profile.Email)
	}
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		h.styles.Title.Render("SUPRESSOR VPN"),
		" ",
		statusIcon,
		statusText,
		" | ",
		h.styles.Subtitle.Render(profileInfo),
	)
}

// renderNetworkLine отображает информацию о сети
func (h *Header) renderNetworkLine() string {
	networkName := "No Network"
	if h.status.NetworkName != "" {
		networkName = h.status.NetworkName
	}
	
	uptime := h.status.Uptime
	if uptime == "" {
		uptime = "0s"
	}
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		h.styles.NetworkInfo.Render("🌐 "+networkName),
		" | ",
		h.styles.TimeInfo.Render("⏱️ "+uptime),
		" | ",
		h.styles.SecurityInfo.Render("🔒 Encrypted"),
	)
}

// renderPeersLine отображает информацию о пирах
func (h *Header) renderPeersLine() string {
	peerCount := h.status.PeerCount
	peerStatus := fmt.Sprintf("👥 %d connected", peerCount)
	
	// Получаем дополнительную информацию о пирах
	var peerDetails string
	if h.networkMgr != nil {
		peers := h.networkMgr.ListPeers()
		trustedCount := 0
		for _, peer := range peers {
			if peer.TrustLevel >= network.TrustHigh {
				trustedCount++
			}
		}
		if trustedCount > 0 {
			peerDetails = fmt.Sprintf(" (%d trusted)", trustedCount)
		}
	}
	
	return h.styles.PeerInfo.Render(peerStatus + peerDetails)
}

// renderTrafficLine отображает информацию о трафике
func (h *Header) renderTrafficLine() string {
	txFormatted := formatBytes(h.status.TxBytes)
	rxFormatted := formatBytes(h.status.RxBytes)
	
	// Расчет скорости
	now := time.Now()
	if !h.lastUpdate.IsZero() {
		elapsed := now.Sub(h.lastUpdate).Seconds()
		if elapsed > 0 {
			// Можно добавить расчет скорости здесь
		}
	}
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		h.styles.TrafficInfo.Render("📤 "+txFormatted),
		" | ",
		h.styles.TrafficInfo.Render("📥 "+rxFormatted),
	)
}

// renderPerformanceLine отображает информацию о производительности
func (h *Header) renderPerformanceLine() string {
	latency := "N/A"
	if h.status.AvgLatency > 0 {
		latency = fmt.Sprintf("%.0fms", h.status.AvgLatency.Seconds()*1000)
	}
	
	packetLoss := "0%"
	if h.status.PacketLoss > 0 {
		packetLoss = fmt.Sprintf("%.1f%%", h.status.PacketLoss*100)
	}
	
	gamingMode := "OFF"
	if h.profile.Settings.GamingMode {
		gamingMode = "ON"
		gamingStyle := h.styles.StatusOnline
		if h.status.AvgLatency > 50*time.Millisecond {
			gamingStyle = h.styles.StatusWarning
		}
		gamingMode = gamingStyle.Render("🎮 " + gamingMode)
	} else {
		gamingMode = h.styles.StatusOffline.Render("🎮 " + gamingMode)
	}
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		h.styles.LatencyInfo.Render("🏓 "+latency),
		" | ",
		h.styles.SecurityInfo.Render("📦 "+packetLoss),
		" | ",
		gamingMode,
	)
}

// renderControlsLine отображает кнопки управления
func (h *Header) renderControlsLine() string {
	buttons := []string{
		h.styles.Button.Render("[H] Hide"),
		h.styles.Button.Render("[C] Collapse"),
		h.styles.Button.Render("[R] Refresh"),
	}
	
	if h.profile.Settings.GamingMode {
		buttons = append(buttons, h.styles.ButtonActive.Render("[G] Gaming ON"))
	} else {
		buttons = append(buttons, h.styles.Button.Render("[G] Gaming OFF"))
	}
	
	if h.profile.Security.TwoFactorEnabled {
		buttons = append(buttons, h.styles.ButtonActive.Render("[S] 2FA ON"))
	} else {
		buttons = append(buttons, h.styles.Button.Render("[S] 2FA OFF"))
	}
	
	buttons = append(buttons, 
		h.styles.TimeInfo.Render(fmt.Sprintf("Updated: %s", 
			h.lastUpdate.Format("15:04:05"))),
	)
	
	return lipgloss.JoinHorizontal(lipgloss.Left, buttons...)
}

// renderNotifications отображает уведомления
func (h *Header) renderNotifications() string {
	// Здесь можно добавить отображение уведомлений из приложения
	// Например: "New peer connected", "Security alert", etc.
	return ""
}

// Вспомогательные функции

func formatBytes(bytes uint64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := uint64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Сообщения для обновления

type UpdateStatusMsg struct{}

type NetworkStatusChangedMsg struct {
	Connected bool
}

type ProfileUpdatedMsg struct {
	Profile *config.Profile
}

type ToggleSecurityMsg struct{}

type ToggleGamingModeMsg struct{}
