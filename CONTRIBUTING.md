# Contributing

Bug reports, ideas and translations are very welcome — see the [issue templates](../../issues/new/choose).

## Build and test

```bash
powershell -ExecutionPolicy Bypass -File build.ps1
```

The script installs a pinned Go toolchain into `.tools` and builds everything into `dist\`. Tests:

```bash
.tools\go\bin\go.exe test ./...
.tools\go\bin\go.exe vet ./...
```

Set `VPNER_MIHOMO` to a `mihomo.exe` to also check generated configs against the real engine. `VPNER_DEV=1` starts the program without administrator rights (no TUN and no kill switch then), `VPNER_DATA` points it to another data folder.

## Project layout

| Path | What is there |
|---|---|
| `cmd/vpner` | the Windows program: tray, window, command line |
| `cmd/vpner-agent` | the Linux agent for WSL and the gateway inside VMs |
| `cmd/vpner-setup` | the installer |
| `internal/providers` | connection types as plugins: a new type is one file with `Register(...)` |
| `internal/engine` | mihomo config generation and process control |
| `internal/agent` | namespaces, VPN daemons, DNS inside tunnels, the VM gateway |
| `internal/bridge`, `internal/wslhost` | the Windows ↔ WSL protocol over stdio |
| `internal/hyperv` | VMs, images, cloud-init, the nftables kill switch |
| `internal/firewall` | the system kill switch |
| `internal/i18n` | texts in every language |
| `internal/web` | the interface (one page) and its API |
| `internal/install` | installing and uninstalling |

## Translations

All texts live in `internal/i18n/locales/<lang>.json`; code refers to them by key (`i18n.T("app.routingIsOn")` in Go, `tr("ui.rules")` and `data-i18n` in the page). To add a language, copy `en.json` to `<lang>.json`, translate the values (keep `%s`/`%v`/`%d` placeholders in the same order) and set `meta.name` to the language's own name. `go test ./internal/i18n` checks that every key is there, that placeholders match and that no text is left in the code.

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `feat(rules): …`, `fix(engine): …`, `docs: …`, `refactor(ui): …`, in English. Work on a branch (`feature/…`, `fix/…`) and open a pull request.
