package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"supressor/internal/utils"
)

// Daemon управляет фоновой службой
type Daemon struct {
	pidFile string
	logFile string
	ctx     context.Context
	cancel  context.CancelFunc
	logger  *utils.Logger
}

func NewDaemon() (*Daemon, error) {
	ctx, cancel := context.WithCancel(context.Background())

	// Определяем пути
	configDir := getConfigDir()
	pidFile := filepath.Join(configDir, "supressor.pid")
	logFile := filepath.Join(configDir, "supressor.log")

	return &Daemon{
		pidFile: pidFile,
		logFile: logFile,
		ctx:     ctx,
		cancel:  cancel,
		logger:  utils.NewLogger("daemon"),
	}, nil
}

// Start запускает демона
func (d *Daemon) Start() error {
	// Проверяем, не запущен ли уже демон
	if d.isRunning() {
		return fmt.Errorf("daemon is already running")
	}

	// Записываем PID
	pid := os.Getpid()
	if err := os.WriteFile(d.pidFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
		return fmt.Errorf("failed to write PID file: %v", err)
	}

	// Настраиваем логирование
	if err := d.setupLogging(); err != nil {
		return fmt.Errorf("failed to setup logging: %v", err)
	}

	d.logger.Info("Supressor daemon started", "pid", pid)

	// Запускаем главный цикл
	go d.run()

	return nil
}

// Stop останавливает демона
func (d *Daemon) Stop() error {
	d.cancel()

	// Удаляем PID файл
	if err := os.Remove(d.pidFile); err != nil && !os.IsNotExist(err) {
		d.logger.Error("Failed to remove PID file", "error", err)
	}

	d.logger.Info("Supressor daemon stopped")
	return nil
}

// Restart перезапускает демона
func (d *Daemon) Restart() error {
	d.logger.Info("Restarting daemon...")

	if err := d.Stop(); err != nil {
		return err
	}

	// Небольшая задержка перед перезапуском
	time.Sleep(1 * time.Second)

	return d.Start()
}

// Status проверяет статус демона
func (d *Daemon) Status() (bool, int, error) {
	if !d.isRunning() {
		return false, 0, nil
	}

	// Читаем PID из файла
	data, err := os.ReadFile(d.pidFile)
	if err != nil {
		return false, 0, err
	}

	var pid int
	if _, err := fmt.Sscanf(string(data), "%d", &pid); err != nil {
		return false, 0, err
	}

	// Проверяем, жив ли процесс
	if err := syscall.Kill(pid, 0); err != nil {
		// Процесс не существует
		os.Remove(d.pidFile)
		return false, 0, nil
	}

	return true, pid, nil
}

// Install устанавливает демона как системную службу
func (d *Daemon) Install() error {
	d.logger.Info("Installing as system service...")

	// Определяем путь к исполняемому файлу
	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("failed to get executable path: %v", err)
	}

	// Создаем systemd service файл
	serviceContent := fmt.Sprintf(`[Unit]
Description=Supressor VPN Daemon
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=%s --daemon
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5
User=root
Group=root
RuntimeDirectory=supressor
StateDirectory=supressor
LogsDirectory=supressor
AmbientCapabilities=CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
`, exePath)

	servicePath := "/etc/systemd/system/supressor.service"
	if err := os.WriteFile(servicePath, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %v", err)
	}

	// Перезагружаем systemd
	cmd := exec.Command("systemctl", "daemon-reload")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %v", err)
	}

	// Включаем автозагрузку
	cmd = exec.Command("systemctl", "enable", "supressor.service")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to enable service: %v", err)
	}

	d.logger.Info("Service installed successfully")
	return nil
}

// Uninstall удаляет системную службу
func (d *Daemon) Uninstall() error {
	d.logger.Info("Uninstalling system service...")

	// Останавливаем службу
	cmd := exec.Command("systemctl", "stop", "supressor.service")
	cmd.Run()

	// Отключаем автозагрузку
	cmd = exec.Command("systemctl", "disable", "supressor.service")
	cmd.Run()

	// Удаляем файл службы
	servicePath := "/etc/systemd/system/supressor.service"
	if err := os.Remove(servicePath); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove service file: %v", err)
	}

	// Перезагружаем systemd
	cmd = exec.Command("systemctl", "daemon-reload")
	cmd.Run()

	d.logger.Info("Service uninstalled successfully")
	return nil
}

// Вспомогательные методы

func (d *Daemon) isRunning() bool {
	_, err := os.Stat(d.pidFile)
	return err == nil
}

func (d *Daemon) setupLogging() error {
	// Создаем или открываем лог-файл
	file, err := os.OpenFile(d.logFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}

	// Настраиваем вывод логов в файл
	d.logger.SetOutput(file)

	return nil
}

func (d *Daemon) run() {
	d.logger.Info("Daemon main loop started")

	// Главный цикл демона
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-d.ctx.Done():
			d.logger.Info("Daemon main loop stopping")
			return
		case <-ticker.C:
			// Периодические задачи
			d.periodicTasks()
		}
	}
}

func (d *Daemon) periodicTasks() {
	// Очистка старых логов
	d.cleanupOldLogs()

	// Проверка обновлений
	d.checkForUpdates()

	// Проверка состояния сети
	d.checkNetworkHealth()

	// Сбор статистики
	d.collectStatistics()
}

func (d *Daemon) cleanupOldLogs() {
	// Реализация очистки старых логов
	// (сохраняем логи за последние 7 дней)
}

func (d *Daemon) checkForUpdates() {
	// Проверка наличия обновлений
}

func (d *Daemon) checkNetworkHealth() {
	// Проверка состояния сети
}

func (d *Daemon) collectStatistics() {
	// Сбор статистики
}

func getConfigDir() string {
	// Возвращает путь к директории конфигурации
	if dir := os.Getenv("SUPRESSOR_CONFIG_DIR"); dir != "" {
		return dir
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "/etc/supressor"
	}

	return filepath.Join(home, ".config", "supressor")
}
