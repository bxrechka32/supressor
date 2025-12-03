package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"supressor/internal/app"
	"supressor/internal/config"
	"supressor/internal/utils"
)

var (
	Version   = "1.0.0"
	BuildTime = "unknown"
)

func main() {
	// Парсинг аргументов командной строки
	var (
		configPath  = flag.String("config", "", "Путь к файлу конфигурации")
		profileName = flag.String("profile", "default", "Имя профиля")
		daemonMode  = flag.Bool("daemon", false, "Запуск в режиме демона")
		logLevel    = flag.String("log-level", "info", "Уровень логирования (debug, info, warn, error)")
		showVersion = flag.Bool("version", false, "Показать версию")
	)
	flag.Parse()

	if *showVersion {
		fmt.Printf("Supressor v%s (built: %s)\n", Version, BuildTime)
		os.Exit(0)
	}

	// Настройка логгера
	logger := utils.NewLogger("main")
	logger.SetLevel(*logLevel)

	// Инициализация контекста с обработкой сигналов
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	// Загрузка конфигурации
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", "error", err)
	}

	// Создание приложения
	app, err := app.New(ctx, cfg, *profileName)
	if err != nil {
		logger.Fatal("Failed to create application", "error", err)
	}

	// Запуск в режиме демона или TUI
	if *daemonMode {
		runAsDaemon(ctx, app, logger)
	} else {
		runTUI(ctx, app, logger)
	}
}

func runAsDaemon(ctx context.Context, app *app.App, logger *utils.Logger) {
	logger.Info("Starting Supressor daemon")

	// Инициализация
	if err := app.Init(); err != nil {
		logger.Fatal("Failed to initialize application", "error", err)
	}

	// Запуск фоновых сервисов
	if err := app.Start(); err != nil {
		logger.Fatal("Failed to start application", "error", err)
	}
	defer app.Stop()

	logger.Info("Supressor daemon started successfully")

	// Ожидание сигнала завершения
	<-ctx.Done()
	logger.Info("Shutting down daemon")
}

func runTUI(ctx context.Context, app *app.App, logger *utils.Logger) {
	// Показать заставку
	showSplashScreen()

	// Создание модели TUI
	model := newTuiModel(ctx, app)

	// Настройка программы TUI
	p := tea.NewProgram(
		model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
		tea.WithFPS(60),
		tea.WithContext(ctx),
	)

	// Запуск приложения
	if err := app.Init(); err != nil {
		logger.Fatal("Failed to initialize application", "error", err)
	}

	// Запуск в горутине для обработки сигналов
	go func() {
		if err := app.Start(); err != nil {
			logger.Error("Failed to start application", "error", err)
			p.Quit()
		}
	}()

	// Запуск TUI
	if _, err := p.Run(); err != nil {
		logger.Fatal("TUI error", "error", err)
	}

	// Остановка приложения
	app.Stop()
}

func showSplashScreen() {
	clearScreen()

	splash := `
███████╗██╗   ██╗██████╗ ██████╗ ███████╗███████╗███████╗ ██████╗ ██████╗ 
██╔════╝██║   ██║██╔══██╗██╔══██╗██╔════╝██╔════╝██╔════╝██╔═══██╗██╔══██╗
███████╗██║   ██║██████╔╝██████╔╝█████╗  ███████╗█████╗  ██║   ██║██████╔╝
╚════██║██║   ██║██╔═══╝ ██╔══██╗██╔══╝  ╚════██║██╔══╝  ██║   ██║██╔══██╗
███████║╚██████╔╝██║     ██║  ██║███████╗███████║███████╗╚██████╔╝██║  ██║
╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
                                                                          
                        Secure VPN with AI Assistant                      
                              Version: ` + Version + `
`

	rainbowColors := []string{
		"#FF0000", "#FF7F00", "#FFFF00", "#00FF00",
		"#0000FF", "#4B0082", "#9400D3",
	}

	lines := splitLines(splash)
	for i, line := range lines {
		color := rainbowColors[i%len(rainbowColors)]
		style := lipgloss.NewStyle().
			Foreground(lipgloss.Color(color)).
			Bold(true)
		fmt.Println(style.Render(line))
	}

	fmt.Println()
	fmt.Println(lipgloss.NewStyle().
		Foreground(lipgloss.Color("#00FFFF")).
		Italic(true).
		Render("Initializing..."))

	time.Sleep(2 * time.Second)
	clearScreen()
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

// TUI Model
type tuiModel struct {
	ctx     context.Context
	app     *app.App
	width   int
	height  int
	current string
	menu    []string
	cursor  int
}

func newTuiModel(ctx context.Context, app *app.App) *tuiModel {
	return &tuiModel{
		ctx:     ctx,
		app:     app,
		current: "main",
		menu: []string{
			"📡 Network Dashboard",
			"👥 Peers",
			"⚙️ Settings",
			"📊 Statistics",
			"🎮 Gaming Mode",
			"🤖 AI Assistant",
			"🔒 Security Scan",
			"❓ Help",
			"🚪 Exit",
		},
	}
}

func (m tuiModel) Init() tea.Cmd {
	return nil
}

func (m tuiModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		return m, nil

	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.menu)-1 {
				m.cursor++
			}
		case "enter", " ":
			return m.handleMenuSelect()
		case "q", "ctrl+c":
			return m, tea.Quit
		case "?":
			m.current = "help"
		case "esc":
			if m.current != "main" {
				m.current = "main"
			}
		}
	}
	return m, nil
}

func (m tuiModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}

	switch m.current {
	case "main":
		return m.renderMainView()
	case "help":
		return m.renderHelpView()
	default:
		return m.renderMainView()
	}
}

func (m tuiModel) renderMainView() string {
	// Header
	header := lipgloss.NewStyle().
		Width(m.width).
		Background(lipgloss.Color("#1E1E2E")).
		Foreground(lipgloss.Color("#CDD6F4")).
		Padding(0, 2).
		Render("Supressor VPN - Secure Networking Platform")

	// Status bar
	status := m.renderStatusBar()

	// Menu
	menuItems := make([]string, len(m.menu))
	for i, item := range m.menu {
		if i == m.cursor {
			menuItems[i] = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#F5C2E7")).
				Background(lipgloss.Color("#575268")).
				Padding(0, 2).
				Render("▶ " + item)
		} else {
			menuItems[i] = lipgloss.NewStyle().
				Foreground(lipgloss.Color("#BAC2DE")).
				Padding(0, 2).
				Render("  " + item)
		}
	}

	menu := lipgloss.JoinVertical(lipgloss.Left, menuItems...)
	menuBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#C9CBFF")).
		Padding(1, 2).
		Width(40).
		Render(menu)

	// Footer
	footer := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#6C7086")).
		Render("↑↓: Navigate • Enter: Select • ?: Help • Q: Quit")

	// Layout
	content := lipgloss.JoinVertical(
		lipgloss.Center,
		header,
		"\n",
		status,
		"\n\n",
		menuBox,
		"\n\n",
		footer,
	)

	return lipgloss.Place(
		m.width, m.height,
		lipgloss.Center, lipgloss.Center,
		content,
	)
}

func (m tuiModel) renderStatusBar() string {
	status := m.app.GetStatus()

	var statusText string
	if status.Connected {
		statusText = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#A6E3A1")).
			Bold(true).
			Render("● CONNECTED")
	} else {
		statusText = lipgloss.NewStyle().
			Foreground(lipgloss.Color("#F38BA8")).
			Bold(true).
			Render("○ DISCONNECTED")
	}

	networkInfo := fmt.Sprintf("Network: %s | Peers: %d", 
		status.NetworkName, status.PeerCount)

	trafficInfo := fmt.Sprintf("↑ %s ↓ %s",
		formatBytes(status.TxBytes), formatBytes(status.RxBytes))

	return lipgloss.JoinHorizontal(
		lipgloss.Center,
		statusText,
		" | ",
		networkInfo,
		" | ",
		trafficInfo,
	)
}

func (m tuiModel) renderHelpView() string {
	help := `
Keyboard Shortcuts:
-------------------
↑/k, ↓/j    Navigate menu
Enter/Space Select item
Esc         Back to main menu
Q, Ctrl+C   Quit application
?           Show this help

Network Commands:
-----------------
C           Create new network
J           Join existing network
L           List available networks
S           Scan network security
G           Toggle gaming mode
A           Toggle AI assistant

Statistics:
-----------
F1          Show real-time stats
F2          Show traffic graph
F3          Show peer latency
F4          Show security alerts
`
	return lipgloss.NewStyle().
		Width(m.width-4).
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#F9E2AF")).
		Render(help)
}

func (m tuiModel) handleMenuSelect() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0: // Network Dashboard
		// Реализовать переход к дашборду
	case 1: // Peers
		// Реализовать список пиров
	case 8: // Exit
		return m, tea.Quit
	}
	return m, nil
}

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
