package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	"supressor/internal/config"
	"supressor/internal/network"
	"supressor/internal/utils"
)

func main() {
	// Команды CLI
	var (
		createNetwork   = flag.String("create", "", "Создать новую сеть")
		joinNetwork     = flag.String("join", "", "Присоединиться к сети")
		listNetworks    = flag.Bool("list", false, "Список сетей")
		status          = flag.Bool("status", false, "Показать статус")
		addPeer         = flag.String("add-peer", "", "Добавить пир (формат: имя:ключ)")
		removePeer      = flag.String("remove-peer", "", "Удалить пир")
		listPeers       = flag.Bool("peers", false, "Список пиров")
		start           = flag.Bool("start", false, "Запустить сеть")
		stop            = flag.Bool("stop", false, "Остановить сеть")
		restart         = flag.Bool("restart", false, "Перезапустить сеть")
		configPath      = flag.String("config", "", "Путь к конфигурации")
		profileName     = flag.String("profile", "default", "Имя профиля")
		logLevel        = flag.String("log-level", "info", "Уровень логирования")
		jsonOutput      = flag.Bool("json", false, "Вывод в формате JSON")
		verbose         = flag.Bool("verbose", false, "Подробный вывод")
		version         = flag.Bool("version", false, "Версия")
	)
	flag.Parse()

	if *version {
		fmt.Println("Supressor CLI v1.0.0")
		return
	}

	// Настройка логгера
	logger := utils.NewLogger("cli")
	if *verbose {
		logger.SetLevel("debug")
	} else {
		logger.SetLevel(*logLevel)
	}

	// Загрузка конфигурации
	cfg, err := config.Load(*configPath)
	if err != nil {
		logger.Fatal("Failed to load config", "error", err)
	}

	// Обработка команд
	switch {
	case *createNetwork != "":
		handleCreateNetwork(*createNetwork, cfg, logger, *jsonOutput)
	case *joinNetwork != "":
		handleJoinNetwork(*joinNetwork, cfg, logger, *jsonOutput)
	case *listNetworks:
		handleListNetworks(cfg, logger, *jsonOutput)
	case *status:
		handleStatus(cfg, logger, *jsonOutput)
	case *addPeer != "":
		handleAddPeer(*addPeer, cfg, logger, *jsonOutput)
	case *removePeer != "":
		handleRemovePeer(*removePeer, cfg, logger, *jsonOutput)
	case *listPeers:
		handleListPeers(cfg, logger, *jsonOutput)
	case *start:
		handleStart(cfg, logger, *jsonOutput)
	case *stop:
		handleStop(cfg, logger, *jsonOutput)
	case *restart:
		handleRestart(cfg, logger, *jsonOutput)
	default:
		showHelp()
	}
}

func handleCreateNetwork(name string, cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	logger.Info("Creating network", "name", name)

	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	networkID, err := nm.CreateNetwork(name)
	if err != nil {
		logError("Failed to create network", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":    "success",
			"network":   name,
			"network_id": networkID,
			"message":   "Network created successfully",
		})
	} else {
		fmt.Printf("✅ Network '%s' created successfully\n", name)
		fmt.Printf("📋 Network ID: %s\n", networkID)
		fmt.Printf("🔑 Public Key: %s\n", nm.GetPublicKey())
	}
}

func handleJoinNetwork(networkInfo string, cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	logger.Info("Joining network", "network", networkInfo)

	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	// Парсим информацию о сети (формат: id:ключ)
	var networkID, networkKey string
	fmt.Sscanf(networkInfo, "%s:%s", &networkID, &networkKey)

	if err := nm.JoinNetwork(networkID, networkKey); err != nil {
		logError("Failed to join network", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "success",
			"network": networkID,
			"message": "Joined network successfully",
		})
	} else {
		fmt.Printf("✅ Joined network '%s'\n", networkID)
		fmt.Printf("📡 Your IP in network: %s\n", nm.GetLocalIP())
	}
}

func handleListNetworks(cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	networks, err := config.ListNetworks()
	if err != nil {
		logError("Failed to list networks", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(networks)
	} else {
		if len(networks) == 0 {
			fmt.Println("No networks found")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tID\tMEMBERS\tCREATED\tSTATUS")
		fmt.Fprintln(w, "----\t--\t-------\t-------\t------")

		for _, net := range networks {
			status := "🟢"
			if !net.Online {
				status = "🔴"
			}
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n",
				net.Name,
				net.ID[:8],
				net.MemberCount,
				net.CreatedAt.Format("2006-01-02"),
				status)
		}
		w.Flush()
	}
}

func handleStatus(cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	status := nm.GetStatus()

	if jsonOutput {
		outputJSON(status)
	} else {
		fmt.Println("📡 Network Status")
		fmt.Println("────────────────")
		fmt.Printf("Connected:      %s\n", boolToStatus(status.Connected))
		fmt.Printf("Network:        %s\n", status.NetworkName)
		fmt.Printf("Interface:      %s\n", status.Interface)
		fmt.Printf("Local IP:       %s\n", status.LocalIP)
		fmt.Printf("Public Key:     %s\n", status.PublicKey)
		fmt.Printf("Peers:          %d connected / %d total\n", 
			status.ConnectedPeers, status.TotalPeers)
		fmt.Printf("Uptime:         %s\n", formatDuration(status.Uptime))
		fmt.Printf("Traffic Up:     %s\n", formatBytes(status.TxBytes))
		fmt.Printf("Traffic Down:   %s\n", formatBytes(status.RxBytes))
		fmt.Printf("Latency:        %s\n", formatDuration(status.AvgLatency))
		fmt.Printf("Packet Loss:    %.2f%%\n", status.PacketLoss*100)
	}
}

func handleAddPeer(peerInfo string, cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	// Парсим информацию о пире (формат: имя:публичный_ключ)
	var name, pubKey string
	fmt.Sscanf(peerInfo, "%s:%s", &name, &pubKey)

	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	if err := nm.AddPeer(name, pubKey); err != nil {
		logError("Failed to add peer", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "success",
			"peer":    name,
			"message": "Peer added successfully",
		})
	} else {
		fmt.Printf("✅ Peer '%s' added successfully\n", name)
	}
}

func handleRemovePeer(peerName string, cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	if err := nm.RemovePeer(peerName); err != nil {
		logError("Failed to remove peer", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "success",
			"peer":    peerName,
			"message": "Peer removed successfully",
		})
	} else {
		fmt.Printf("✅ Peer '%s' removed successfully\n", peerName)
	}
}

func handleListPeers(cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	peers := nm.ListPeers()

	if jsonOutput {
		outputJSON(peers)
	} else {
		if len(peers) == 0 {
			fmt.Println("No peers found")
			return
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tIP\tSTATUS\tLATENCY\tLAST SEEN\tTRAFFIC")
		fmt.Fprintln(w, "----\t--\t------\t-------\t---------\t-------")

		for _, peer := range peers {
			status := "🟢"
			if !peer.Online {
				status = "🔴"
			}

			traffic := fmt.Sprintf("↑%s ↓%s",
				formatBytes(peer.TxBytes),
				formatBytes(peer.RxBytes))

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
				peer.Name,
				peer.IP,
				status,
				formatDuration(peer.Latency),
				formatTime(peer.LastSeen),
				traffic)
		}
		w.Flush()
	}
}

func handleStart(cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	if err := nm.Start(); err != nil {
		logError("Failed to start network", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "success",
			"message": "Network started successfully",
		})
	} else {
		fmt.Println("✅ Network started successfully")
	}
}

func handleStop(cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	if err := nm.Stop(); err != nil {
		logError("Failed to stop network", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "success",
			"message": "Network stopped successfully",
		})
	} else {
		fmt.Println("✅ Network stopped successfully")
	}
}

func handleRestart(cfg *config.Config, logger *utils.Logger, jsonOutput bool) {
	nm, err := network.NewManager(cfg)
	if err != nil {
		logError("Failed to create network manager", err, jsonOutput)
		os.Exit(1)
	}

	if err := nm.Restart(); err != nil {
		logError("Failed to restart network", err, jsonOutput)
		os.Exit(1)
	}

	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "success",
			"message": "Network restarted successfully",
		})
	} else {
		fmt.Println("✅ Network restarted successfully")
	}
}

// Вспомогательные функции

func showHelp() {
	fmt.Println(`Supressor CLI - Secure VPN Management

Usage:
  supressor-cli [command] [options]

Commands:
  --create <name>        Create a new network
  --join <id:key>        Join an existing network
  --list                 List available networks
  --status               Show current status
  --add-peer <name:key>  Add a peer to network
  --remove-peer <name>   Remove a peer from network
  --peers                List peers in current network
  --start                Start the network
  --stop                 Stop the network
  --restart              Restart the network

Options:
  --config <path>        Configuration file path
  --profile <name>       Profile name (default: default)
  --log-level <level>    Log level (debug, info, warn, error)
  --json                 Output in JSON format
  --verbose              Verbose output
  --version              Show version

Examples:
  supressor-cli --create "My Network"
  supressor-cli --join "net123:public_key_here"
  supressor-cli --status
  supressor-cli --add-peer "alice:pubkey123"
  supressor-cli --peers --json`)
}

func logError(message string, err error, jsonOutput bool) {
	if jsonOutput {
		outputJSON(map[string]string{
			"status":  "error",
			"message": message,
			"error":   err.Error(),
		})
	} else {
		fmt.Printf("❌ %s: %v\n", message, err)
	}
}

func outputJSON(data interface{}) {
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(jsonData))
}

func boolToStatus(b bool) string {
	if b {
		return "🟢 Yes"
	}
	return "🔴 No"
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

func formatBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%dB", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(b)/float64(div), "KMGTPE"[exp])
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "Never"
	}
	diff := time.Since(t)
	if diff < time.Minute {
		return "Just now"
	}
	if diff < time.Hour {
		return fmt.Sprintf("%dm ago", int(diff.Minutes()))
	}
	if diff < 24*time.Hour {
		return fmt.Sprintf("%dh ago", int(diff.Hours()))
	}
	return t.Format("2006-01-02")
}
