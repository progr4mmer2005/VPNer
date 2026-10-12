package providers

import (
	"strconv"

	"vpner/internal/config"
)

// A dedicated Hyper-V virtual machine running the original desktop VPN
// application. VPNer creates and configures the VM automatically.
type hypervProvider struct{}

func init() { Register(hypervProvider{}) }

func (hypervProvider) Type() string     { return "hyperv" }
func (hypervProvider) Title() string    { return "Виртуалка для VPN-программы" }
func (hypervProvider) Runtime() Runtime { return RuntimeVM }
func (hypervProvider) Description() string {
	return "Отдельная виртуальная машина Hyper-V с Linux и рабочим столом — для оригинальных программ (AmneziaVPN, Cisco Secure Client, клиенты провайдеров). VPNer сам скачает систему, создаст и настроит ВМ; вы ставите туда VPN-программу и подключаетесь. Трафик шлюза в ВМ может идти только через туннель этой программы."
}

func (hypervProvider) Fields() []Field {
	return []Field{
		{Key: "memory", Label: "Память ВМ, МБ", Kind: "number", Default: "3072", Help: "2048 — минимум для рабочего стола, 4096 — комфортно."},
		{Key: "cpus", Label: "Процессоров", Kind: "number", Default: "2"},
		{Key: "desktop", Label: "Рабочий стол и браузер", Kind: "bool", Default: "true", Help: "Нужен для графических VPN-программ и входа через браузер. Без него ВМ легче, но программа должна работать из консоли."},
		{Key: "disk", Label: "Размер диска, ГБ", Kind: "number", Default: "24", Advanced: true},
		fieldFallbackDNS(),
	}
}

func atoiDefault(s string, def, minv, maxv int) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return max(minv, min(maxv, n))
}

func (hypervProvider) VM(c *config.Connection) (*VMSpec, error) {
	return &VMSpec{
		VMName:   "VPNer - " + c.ID,
		MemoryMB: atoiDefault(c.P("memory"), 3072, 1024, 65536),
		CPUs:     atoiDefault(c.P("cpus"), 2, 1, 64),
		DiskGB:   atoiDefault(c.P("disk"), 24, 8, 2048),
		Desktop:  boolDefault(c, "desktop", true),
		DNS:      dnsList(c),
	}, nil
}
