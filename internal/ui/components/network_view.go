package components

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"supressor/internal/app"
	"supressor/internal/network"
	"supressor/internal/utils"
)

// NetworkView представляет вид сети
type NetworkView struct {
	width      int
	height     int
	app        *app.App
	networkMgr *network.Manager
	peers      []*network.Peer
	stats      *network.Stats
	selected   int
	offset     int
	viewMode   ViewMode
	filter     string
	sortBy     SortBy
	sortDesc   bool
	lastUpdate time.Time
	styles     *NetworkStyles
	logger     *utils.Logger
}

// ViewMode определяет режим отображения
type ViewMode int

const (
	ViewList ViewMode = iota
	ViewGrid
	ViewGraph
	ViewDetails
)

// SortBy определяет поле сортировки
type SortBy int

const (
	SortByName SortBy = iota
	SortByLatency
	SortByTraffic
	SortByTrust
	SortByConnectionTime
)

// NetworkStyles определяет стили вида сети
type NetworkStyles struct {
	Container       lipgloss.Style
	Title           lipgloss.Style
	Subtitle        lipgloss.Style
	PeerOnline      lipgloss.Style
	PeerOffline     lipgloss.Style
	PeerSelected    lipgloss.Style
	PeerTrustHigh   lipgloss.Style
	PeerTrustMedium lipgloss.Style
	PeerTrustLow    lipgloss.Style
	PeerTrustUnknown lipgloss.Style
	StatsBox        lipgloss.Style
	StatsTitle      lipgloss.Style
	StatsValue      lipgloss.Style
	StatsLabel      lipgloss.Style
	Button          lipgloss.Style
	ButtonActive    lipgloss.Style
	SearchBox       lipgloss.Style
	FilterActive    lipgloss.Style
	FilterInactive  lipgloss.Style
	StatusBar       lipgloss.Style
	HelpText        lipgloss.Style
	GraphBar        lipgloss.Style
	GraphAxis       lipgloss.Style
	GraphLabel      lipgloss.Style
}

// NewNetworkView создает новый вид сети
func NewNetworkView(app *app.App, width, height int) *NetworkView {
	logger := utils.NewLogger("ui:network")
	
	view := &NetworkView{
		width:      width,
		height:     height,
		app:        app,
		networkMgr: app.GetNetworkManager(),
		viewMode:   ViewList,
		sortBy:     SortByName,
		styles:     NewNetworkStyles(),
		logger:     logger,
	}
	
	// Загрузка начальных данных
	view.refreshData()
	
	return view
}

// NewNetworkStyles создает стили вида сети
func NewNetworkStyles() *NetworkStyles {
	return &NetworkStyles{
		Container: lipgloss.NewStyle().
			Padding(1).
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#555555")),
		
		Title: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF6B9D")).
			Bold(true).
			MarginBottom(1),
		
		Subtitle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#58C4DD")).
			Italic(true).
			MarginBottom(1),
		
		PeerOnline: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Bold(true),
		
		PeerOffline: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FF3333")),
		
		PeerSelected: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5555FF")).
			Padding(0, 1),
		
		PeerTrustHigh: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")),
		
		PeerTrustMedium: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFF00")),
		
		PeerTrustLow: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFA500")),
		
		PeerTrustUnknown: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")),
		
		StatsBox: lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("#333333")).
			Padding(1).
			Width(30),
		
		StatsTitle: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Bold(true).
			MarginBottom(1),
		
		StatsValue: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FFFF")).
			Bold(true),
		
		StatsLabel: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")),
		
		Button: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#CCCCCC")).
			Background(lipgloss.Color("#333333")).
			Padding(0, 1).
			MarginRight(1),
		
		ButtonActive: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#5555FF")).
			Padding(0, 1).
			MarginRight(1).
			Bold(true),
		
		SearchBox: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#FFFFFF")).
			Background(lipgloss.Color("#222222")).
			Padding(0, 1).
			Width(20),
		
		FilterActive: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#00FF00")).
			Bold(true),
		
		FilterInactive: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")),
		
		StatusBar: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			Padding(0, 1),
		
		HelpText: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#555555")).
			Italic(true),
		
		GraphBar: lipgloss.NewStyle().
			Background(lipgloss.Color("#00FF00")),
		
		GraphAxis: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#333333")),
		
		GraphLabel: lipgloss.NewStyle().
			Foreground(lipgloss.Color("#888888")).
			FontSize(10),
	}
}

// Init инициализирует вид сети
func (nv *NetworkView) Init() tea.Cmd {
	// Запуск обновления данных каждые 5 секунд
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return RefreshDataMsg{}
	})
}

// Update обновляет состояние вида сети
func (nv *NetworkView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		nv.width = msg.Width
		nv.height = msg.Height
		
	case RefreshDataMsg:
		nv.refreshData()
		// Планируем следующее обновление
		return nv, tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
			return RefreshDataMsg{}
		})
		
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if nv.selected > 0 {
				nv.selected--
				if nv.selected < nv.offset {
					nv.offset = nv.selected
				}
			}
		case "down", "j":
			if nv.selected < len(nv.peers)-1 {
				nv.selected++
				visibleItems := nv.getVisibleItems()
				if nv.selected >= nv.offset+visibleItems {
					nv.offset = nv.selected - visibleItems + 1
				}
			}
		case "enter", " ":
			if nv.selected < len(nv.peers) {
				return nv, nv.selectPeer(nv.peers[nv.selected])
			}
		case "l":
			nv.viewMode = ViewList
		case "g":
			nv.viewMode = ViewGrid
		case "r":
			nv.viewMode = ViewGraph
		case "d":
			nv.viewMode = ViewDetails
		case "n":
			nv.sortBy = SortByName
			nv.sortPeers()
		case "t":
			nv.sortBy = SortByLatency
			nv.sortPeers()
		case "b":
			nv.sortBy = SortByTraffic
			nv.sortPeers()
		case "u":
			nv.sortBy = SortByTrust
			nv.sortPeers()
		case "c":
			nv.sortBy = SortByConnectionTime
			nv.sortPeers()
		case "R":
			nv.sortDesc = !nv.sortDesc
			nv.sortPeers()
		case "f":
			// Переключение фильтра
			return nv, tea.Cmd(func() tea.Msg {
				return ToggleFilterMsg{}
			})
		case "s":
			// Поиск
			return nv, tea.Cmd(func() tea.Msg {
				return StartSearchMsg{}
			})
		case "esc":
			nv.filter = ""
		case "?":
			return nv, tea.Cmd(func() tea.Msg {
				return ShowHelpMsg{Component: "network"}
			})
		}
		
	case PeerSelectedMsg:
		// Обработка выбора пира
		nv.logger.Info("Peer selected", "peer", msg.Peer.Name)
		
	case NetworkUpdatedMsg:
		nv.refreshData()
	}
	
	return nv, nil
}

// View отображает вид сети
func (nv *NetworkView) View() string {
	if nv.width <= 0 || nv.height <= 0 {
		return "Loading..."
	}
	
	// Высота контента (минус заголовок и статус бар)
	contentHeight := nv.height - 4
	
	switch nv.viewMode {
	case ViewList:
		return nv.renderListView(contentHeight)
	case ViewGrid:
		return nv.renderGridView(contentHeight)
	case ViewGraph:
		return nv.renderGraphView(contentHeight)
	case ViewDetails:
		return nv.renderDetailedView(contentHeight)
	default:
		return nv.renderListView(contentHeight)
	}
}

// refreshData обновляет данные
func (nv *NetworkView) refreshData() {
	if nv.networkMgr != nil {
		nv.peers = nv.networkMgr.ListPeers()
		nv.stats = nv.networkMgr.GetStats()
		nv.sortPeers()
		nv.lastUpdate = time.Now()
	}
}

// sortPeers сортирует пиров
func (nv *NetworkView) sortPeers() {
	if len(nv.peers) == 0 {
		return
	}
	
	sort.Slice(nv.peers, func(i, j int) bool {
		a := nv.peers[i]
		b := nv.peers[j]
		
		var less bool
		switch nv.sortBy {
		case SortByName:
			less = a.Name < b.Name
		case SortByLatency:
			less = a.Latency < b.Latency
		case SortByTraffic:
			totalA := a.RxBytes + a.TxBytes
			totalB := b.RxBytes + b.TxBytes
			less = totalA > totalB // Больше трафика = выше
		case SortByTrust:
			less = a.TrustLevel > b.TrustLevel // Выше доверие = выше
		case SortByConnectionTime:
			less = a.ConnectionTime > b.ConnectionTime
		default:
			less = a.Name < b.Name
		}
		
		if nv.sortDesc {
			return !less
		}
		return less
	})
}

// getVisibleItems возвращает количество видимых элементов
func (nv *NetworkView) getVisibleItems() int {
	// Высота минус заголовки и панель управления
	return nv.height - 8
}

// renderListView отображает список пиров
func (nv *NetworkView) renderListView(contentHeight int) string {
	// Заголовок
	title := nv.renderTitle()
	
	// Панель управления
	controls := nv.renderControls()
	
	// Список пиров
	peerList := nv.renderPeerList(contentHeight - 4)
	
	// Статистика
	stats := nv.renderStats()
	
	// Статус бар
	statusBar := nv.renderStatusBar()
	
	// Сборка
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		controls,
		lipgloss.JoinHorizontal(
			lipgloss.Top,
			peerList,
			"  ",
			stats,
		),
		statusBar,
	)
	
	return nv.styles.Container.
		Width(nv.width - 2).
		Height(nv.height - 2).
		Render(content)
}

// renderGridView отображает сетку пиров
func (nv *NetworkView) renderGridView(contentHeight int) string {
	title := nv.renderTitle()
	controls := nv.renderControls()
	
	// Расчет сетки
	cols := max(1, nv.width/30)
	rows := (len(nv.peers) + cols - 1) / cols
	
	var grid [][]string
	for i := 0; i < rows; i++ {
		var row []string
		for j := 0; j < cols; j++ {
			idx := i*cols + j
			if idx < len(nv.peers) {
				peer := nv.peers[idx]
				row = append(row, nv.renderPeerCard(peer, idx == nv.selected))
			} else {
				row = append(row, "")
			}
		}
		grid = append(grid, row)
	}
	
	// Отображение сетки
	var gridRows []string
	for _, row := range grid {
		gridRows = append(gridRows, lipgloss.JoinHorizontal(lipgloss.Top, row...))
	}
	peerGrid := lipgloss.JoinVertical(lipgloss.Left, gridRows...)
	
	statusBar := nv.renderStatusBar()
	
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		controls,
		peerGrid,
		statusBar,
	)
	
	return nv.styles.Container.Render(content)
}

// renderGraphView отображает графики
func (nv *NetworkView) renderGraphView(contentHeight int) string {
	title := nv.renderTitle()
	controls := nv.renderControls()
	
	// График трафика
	trafficGraph := nv.renderTrafficGraph()
	
	// График задержек
	latencyGraph := nv.renderLatencyGraph()
	
	// Статистика
	stats := nv.renderDetailedStats()
	
	statusBar := nv.renderStatusBar()
	
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		controls,
		trafficGraph,
		latencyGraph,
		stats,
		statusBar,
	)
	
	return nv.styles.Container.Render(content)
}

// renderDetailedView отображает детальный вид
func (nv *NetworkView) renderDetailedView(contentHeight int) string {
	if nv.selected >= len(nv.peers) {
		return "No peer selected"
	}
	
	peer := nv.peers[nv.selected]
	
	title := nv.renderTitle()
	controls := nv.renderControls()
	
	// Детальная информация о пире
	peerDetails := nv.renderPeerDetails(peer)
	
	// Статистика пира
	peerStats := nv.renderPeerStats(peer)
	
	statusBar := nv.renderStatusBar()
	
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		title,
		controls,
		peerDetails,
		peerStats,
		statusBar,
	)
	
	return nv.styles.Container.Render(content)
}

// renderTitle отображает заголовок
func (nv *NetworkView) renderTitle() string {
	networkName := "No Network"
	if nv.stats != nil && nv.app.GetStatus().NetworkName != "" {
		networkName = nv.app.GetStatus().NetworkName
	}
	
	peerCount := len(nv.peers)
	connectedCount := 0
	for _, peer := range nv.peers {
		if peer.IsConnected {
			connectedCount++
		}
	}
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		nv.styles.Title.Render("Network: "+networkName),
		" ",
		nv.styles.Subtitle.Render(fmt.Sprintf("(%d/%d peers online)", 
			connectedCount, peerCount)),
	)
}

// renderControls отображает панель управления
func (nv *NetworkView) renderControls() string {
	viewButtons := []string{
		nv.getViewButton("List [L]", ViewList),
		nv.getViewButton("Grid [G]", ViewGrid),
		nv.getViewButton("Graph [R]", ViewGraph),
		nv.getViewButton("Details [D]", ViewDetails),
	}
	
	sortButtons := []string{
		nv.getSortButton("Name [N]", SortByName),
		nv.getSortButton("Latency [T]", SortByLatency),
		nv.getSortButton("Traffic [B]", SortByTraffic),
		nv.getSortButton("Trust [U]", SortByTrust),
		nv.getSortButton("Time [C]", SortByConnectionTime),
	}
	
	if nv.filter != "" {
		sortButtons = append(sortButtons, 
			nv.styles.FilterActive.Render(fmt.Sprintf("Filter: %s [ESC]", nv.filter)))
	} else {
		sortButtons = append(sortButtons, 
			nv.styles.FilterInactive.Render("Filter [F]"))
	}
	
	return lipgloss.JoinVertical(
		lipgloss.Left,
		lipgloss.JoinHorizontal(lipgloss.Left, viewButtons...),
		lipgloss.JoinHorizontal(lipgloss.Left, sortButtons...),
	)
}

// renderPeerList отображает список пиров
func (nv *NetworkView) renderPeerList(height int) string {
	if len(nv.peers) == 0 {
		return nv.styles.HelpText.Render("No peers in network")
	}
	
	visibleItems := min(height, len(nv.peers))
	var items []string
	
	for i := nv.offset; i < nv.offset+visibleItems && i < len(nv.peers); i++ {
		peer := nv.peers[i]
		item := nv.renderPeerListItem(peer, i == nv.selected)
		items = append(items, item)
	}
	
	return lipgloss.JoinVertical(lipgloss.Left, items...)
}

// renderPeerListItem отображает элемент списка пиров
func (nv *NetworkView) renderPeerListItem(peer *network.Peer, selected bool) string {
	statusIcon := "🔴"
	statusStyle := nv.styles.PeerOffline
	
	if peer.IsConnected {
		statusIcon = "🟢"
		statusStyle = nv.styles.PeerOnline
	}
	
	trustStyle := nv.getTrustStyle(peer.TrustLevel)
	
	// Форматирование информации
	name := fmt.Sprintf("%-20s", peer.Name)
	latency := "N/A"
	if peer.Latency > 0 {
		latency = fmt.Sprintf("%.0fms", peer.Latency.Seconds()*1000)
	}
	traffic := formatBytes(peer.RxBytes + peer.TxBytes)
	
	line := fmt.Sprintf("%s %s %s %s %s",
		statusIcon,
		name,
		trustStyle.Render(getTrustSymbol(peer.TrustLevel)),
		latency,
		traffic,
	)
	
	if selected {
		return nv.styles.PeerSelected.Render(line)
	}
	
	return statusStyle.Render(line)
}

// renderPeerCard отображает карточку пира
func (nv *NetworkView) renderPeerCard(peer *network.Peer, selected bool) string {
	width := 28
	statusIcon := "🔴"
	statusColor := "#FF3333"
	
	if peer.IsConnected {
		statusIcon = "🟢"
		statusColor = "#00FF00"
	}
	
	cardStyle := lipgloss.NewStyle().
		Width(width).
		Padding(1).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333333"))
	
	if selected {
		cardStyle = cardStyle.
			BorderForeground(lipgloss.Color("#5555FF")).
			Background(lipgloss.Color("#222244"))
	}
	
	// Информация о пире
	name := lipgloss.NewStyle().
		Foreground(lipgloss.Color("#FFFFFF")).
		Bold(true).
		Width(width - 2).
		Render(truncate(peer.Name, width-2))
	
	status := lipgloss.NewStyle().
		Foreground(lipgloss.Color(statusColor)).
		Render(fmt.Sprintf("%s %s", statusIcon, 
			getConnectionStatus(peer.IsConnected)))
	
	latency := "Latency: N/A"
	if peer.Latency > 0 {
		latency = fmt.Sprintf("Latency: %.0fms", peer.Latency.Seconds()*1000)
	}
	
	traffic := fmt.Sprintf("Traffic: %s", 
		formatBytes(peer.RxBytes + peer.TxBytes))
	
	trust := lipgloss.NewStyle().
		Foreground(nv.getTrustColor(peer.TrustLevel)).
		Render(fmt.Sprintf("Trust: %s", getTrustLevelName(peer.TrustLevel)))
	
	content := lipgloss.JoinVertical(
		lipgloss.Left,
		name,
		status,
		latency,
		traffic,
		trust,
	)
	
	return cardStyle.Render(content)
}

// renderStats отображает статистику
func (nv *NetworkView) renderStats() string {
	if nv.stats == nil {
		return ""
	}
	
	lines := []string{
		nv.styles.StatsTitle.Render("Network Stats"),
		"",
		nv.renderStatLine("Total Traffic", 
			formatBytes(nv.stats.TotalRxBytes+nv.stats.TotalTxBytes)),
		nv.renderStatLine("Active Peers", fmt.Sprintf("%d", nv.stats.ActivePeers)),
		nv.renderStatLine("Avg Latency", 
			fmt.Sprintf("%.0fms", nv.stats.AverageLatency.Seconds()*1000)),
		nv.renderStatLine("Packet Loss", 
			fmt.Sprintf("%.1f%%", nv.stats.PacketLoss*100)),
		nv.renderStatLine("Uptime", formatDuration(nv.stats.Uptime)),
	}
	
	return nv.styles.StatsBox.Render(
		lipgloss.JoinVertical(lipgloss.Left, lines...))
}

// renderDetailedStats отображает детальную статистику
func (nv *NetworkView) renderDetailedStats() string {
	if nv.stats == nil {
		return ""
	}
	
	statsBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		Padding(1).
		Width(40)
	
	lines := []string{
		nv.styles.StatsTitle.Render("Detailed Statistics"),
		"",
		nv.renderStatLine("Total RX", formatBytes(nv.stats.TotalRxBytes)),
		nv.renderStatLine("Total TX", formatBytes(nv.stats.TotalTxBytes)),
		nv.renderStatLine("Throughput Up", 
			formatBytes(nv.stats.ThroughputUp)+"/s"),
		nv.renderStatLine("Throughput Down", 
			formatBytes(nv.stats.ThroughputDown)+"/s"),
		nv.renderStatLine("Min Latency", 
			fmt.Sprintf("%.0fms", nv.stats.MinLatency.Seconds()*1000)),
		nv.renderStatLine("Max Latency", 
			fmt.Sprintf("%.0fms", nv.stats.MaxLatency.Seconds()*1000)),
		nv.renderStatLine("Avg Jitter", 
			fmt.Sprintf("%.0fms", nv.stats.AverageJitter.Seconds()*1000)),
		nv.renderStatLine("Total Packets", 
			formatNumber(nv.stats.TotalPackets)),
	}
	
	// Статистика по протоколам
	if len(nv.stats.ProtocolStats) > 0 {
		lines = append(lines, "")
		lines = append(lines, nv.styles.StatsTitle.Render("Protocol Stats"))
		for proto, count := range nv.stats.ProtocolStats {
			lines = append(lines, nv.renderStatLine(proto, formatNumber(count)))
		}
	}
	
	return statsBox.Render(
		lipgloss.JoinVertical(lipgloss.Left, lines...))
}

// renderTrafficGraph отображает график трафика
func (nv *NetworkView) renderTrafficGraph() string {
	height := 10
	width := nv.width - 20
	
	// Создаем простой ASCII график
	var graph []string
	
	// Ось Y
	for i := height; i >= 0; i-- {
		var line strings.Builder
		line.WriteString(fmt.Sprintf("%3d │ ", i*10))
		
		// Пример данных (в реальном приложении используйте реальные данные)
		value := (height - i) * 10
		for j := 0; j < width-5; j++ {
			if j < value/2 {
				line.WriteString("█")
			} else {
				line.WriteString(" ")
			}
		}
		graph = append(graph, line.String())
	}
	
	// Ось X
	axis := "    └"
	for i := 0; i < width-5; i++ {
		axis += "─"
	}
	graph = append(graph, axis)
	
	// Подписи
	labels := "     "
	for i := 0; i < 5; i++ {
		labels += fmt.Sprintf("%-*s", (width-5)/5, fmt.Sprintf("%dh", i*6))
	}
	graph = append(graph, labels)
	
	return lipgloss.JoinVertical(lipgloss.Left, graph...)
}

// renderLatencyGraph отображает график задержек
func (nv *NetworkView) renderLatencyGraph() string {
	height := 8
	width := nv.width - 20
	
	var graph []string
	graph = append(graph, nv.styles.StatsTitle.Render("Latency History"))
	
	// Пример данных
	data := []int{50, 45, 60, 55, 40, 35, 50, 65, 70, 55}
	maxVal := 0
	for _, val := range data {
		if val > maxVal {
			maxVal = val
		}
	}
	
	for i := height; i >= 0; i-- {
		var line strings.Builder
		threshold := float64(i) / float64(height) * float64(maxVal)
		
		for _, val := range data {
			if float64(val) >= threshold {
				line.WriteString("█")
			} else {
				line.WriteString(" ")
			}
			line.WriteString(" ")
		}
		
		if i == height {
			line.WriteString(fmt.Sprintf(" %dms", maxVal))
		} else if i == 0 {
			line.WriteString(" 0ms")
		}
		
		graph = append(graph, line.String())
	}
	
	return lipgloss.JoinVertical(lipgloss.Left, graph...)
}

// renderPeerDetails отображает детали пира
func (nv *NetworkView) renderPeerDetails(peer *network.Peer) string {
	detailsBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		Padding(1).
		Width(nv.width - 4)
	
	lines := []string{
		nv.styles.StatsTitle.Render("Peer Details: " + peer.Name),
		"",
		nv.renderDetailLine("ID", peer.ID),
		nv.renderDetailLine("Public Key", truncate(peer.PublicKey, 40)),
		nv.renderDetailLine("Status", getConnectionStatus(peer.IsConnected)),
		nv.renderDetailLine("Trust Level", getTrustLevelName(peer.TrustLevel)),
		nv.renderDetailLine("Connection Time", formatDuration(peer.ConnectionTime)),
		nv.renderDetailLine("Last Seen", peer.LastSeen.Format("2006-01-02 15:04:05")),
	}
	
	if peer.Endpoint != nil {
		lines = append(lines, 
			nv.renderDetailLine("Endpoint", peer.Endpoint.String()))
	}
	
	if peer.DeviceInfo != nil {
		lines = append(lines,
			nv.renderDetailLine("Device", peer.DeviceInfo.Hostname),
			nv.renderDetailLine("OS", peer.DeviceInfo.OS),
			nv.renderDetailLine("Version", peer.DeviceInfo.AppVersion),
		)
	}
	
	if peer.GeoLocation != nil {
		lines = append(lines,
			nv.renderDetailLine("Location", 
				fmt.Sprintf("%s, %s", peer.GeoLocation.City, peer.GeoLocation.Country)),
			nv.renderDetailLine("ISP", peer.GeoLocation.ISP),
		)
	}
	
	return detailsBox.Render(
		lipgloss.JoinVertical(lipgloss.Left, lines...))
}

// renderPeerStats отображает статистику пира
func (nv *NetworkView) renderPeerStats(peer *network.Peer) string {
	statsBox := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#333333")).
		Padding(1).
		Width(nv.width - 4)
	
	lines := []string{
		nv.styles.StatsTitle.Render("Peer Statistics"),
		"",
		nv.renderStatLine("RX Traffic", formatBytes(peer.RxBytes)),
		nv.renderStatLine("TX Traffic", formatBytes(peer.TxBytes)),
		nv.renderStatLine("Total Traffic", 
			formatBytes(peer.RxBytes+peer.TxBytes)),
		nv.renderStatLine("Latency", 
			fmt.Sprintf("%.0fms", peer.Latency.Seconds()*1000)),
		nv.renderStatLine("Jitter", 
			fmt.Sprintf("%.0fms", peer.Jitter.Seconds()*1000)),
		nv.renderStatLine("Packet Loss", 
			fmt.Sprintf("%.1f%%", peer.PacketLoss*100)),
	}
	
	return statsBox.Render(
		lipgloss.JoinVertical(lipgloss.Left, lines...))
}

// renderStatusBar отображает статус бар
func (nv *NetworkView) renderStatusBar() string {
	status := fmt.Sprintf("Peers: %d | Selected: %d | Updated: %s",
		len(nv.peers),
		nv.selected+1,
		nv.lastUpdate.Format("15:04:05"),
	)
	
	help := "[↑↓] Navigate [Enter] Select [L/G/R/D] Views [F] Filter [S] Search [?] Help"
	
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		nv.styles.StatusBar.Render(status),
		" | ",
		nv.styles.HelpText.Render(help),
	)
}

// Вспомогательные методы

func (nv *NetworkView) getViewButton(text string, mode ViewMode) string {
	if nv.viewMode == mode {
		return nv.styles.ButtonActive.Render(text)
	}
	return nv.styles.Button.Render(text)
}

func (nv *NetworkView) getSortButton(text string, sortBy SortBy) string {
	if nv.sortBy == sortBy {
		arrow := "↑"
		if nv.sortDesc {
			arrow = "↓"
		}
		return nv.styles.ButtonActive.Render(text + " " + arrow)
	}
	return nv.styles.Button.Render(text)
}

func (nv *NetworkView) getTrustStyle(trust network.TrustLevel) lipgloss.Style {
	switch trust {
	case network.TrustSystem:
		return nv.styles.PeerTrustHigh
	case network.TrustHigh:
		return nv.styles.PeerTrustHigh
	case network.TrustMedium:
		return nv.styles.PeerTrustMedium
	case network.TrustLow:
		return nv.styles.PeerTrustLow
	default:
		return nv.styles.PeerTrustUnknown
	}
}

func (nv *NetworkView) getTrustColor(trust network.TrustLevel) lipgloss.Color {
	switch trust {
	case network.TrustSystem, network.TrustHigh:
		return lipgloss.Color("#00FF00")
	case network.TrustMedium:
		return lipgloss.Color("#FFFF00")
	case network.TrustLow:
		return lipgloss.Color("#FFA500")
	default:
		return lipgloss.Color("#888888")
	}
}

func (nv *NetworkView) renderStatLine(label, value string) string {
	return lipgloss.JoinHorizontal(
		lipgloss.Left,
		nv.styles.StatsLabel.Render(label+": "),
		nv.styles.StatsValue.Render(value),
	)
}

func (nv *NetworkView) renderDetailLine(label, value string) string {
	return fmt.Sprintf("%-15s: %s", label, value)
}

func (nv *NetworkView) selectPeer(peer *network.Peer) tea.Cmd {
	return func() tea.Msg {
		return PeerSelectedMsg{Peer: peer}
	}
}

// Вспомогательные функции

func getConnectionStatus(connected bool) string {
	if connected {
		return "Connected"
	}
	return "Disconnected"
}

func getTrustLevelName(trust network.TrustLevel) string {
	switch trust {
	case network.TrustSystem:
		return "System"
	case network.TrustHigh:
		return "High"
	case network.TrustMedium:
		return "Medium"
	case network.TrustLow:
		return "Low"
	default:
		return "Unknown"
	}
}

func getTrustSymbol(trust network.TrustLevel) string {
	switch trust {
	case network.TrustSystem:
		return "🔐"
	case network.TrustHigh:
		return "🟢"
	case network.TrustMedium:
		return "🟡"
	case network.TrustLow:
		return "🟠"
	default:
		return "⚪"
	}
}

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

func formatNumber(n uint64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	suffixes := []string{"K", "M", "B", "T"}
	value := float64(n)
	for _, suffix := range suffixes {
		value /= 1000
		if value < 1000 {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fT", value/1000)
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Сообщения

type RefreshDataMsg struct{}

type PeerSelectedMsg struct {
	Peer *network.Peer
}

type NetworkUpdatedMsg struct{}

type ToggleFilterMsg struct{}

type StartSearchMsg struct{}

type ShowHelpMsg struct {
	Component string
}
