<p align="center">
  <img src="assets/hero.svg" alt="Seckit" width="100%">
</p>

<p align="center">
  <b>Локальная проверка безопасности проекта для Claude Code, Codex, Cursor и OpenCode.</b><br>
  Русский · <a href="README.en.md">English</a>
</p>

<p align="center">
  <a href="https://pypi.org/project/seckit/"><img alt="PyPI" src="https://img.shields.io/pypi/v/seckit?color=3776ab"></a>
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white">
  <img alt="Linux · macOS · WSL" src="https://img.shields.io/badge/Linux%20·%20macOS%20·%20WSL-0f172a">
  <img alt="Trivy + Semgrep" src="https://img.shields.io/badge/Trivy%20%2B%20Semgrep-10b981">
  <a href="LICENSE"><img alt="FSL-1.1-ALv2" src="https://img.shields.io/badge/license-FSL--1.1--ALv2-64748b"></a>
</p>

Seckit ищет уязвимости, а ваш агент разбирает находки и исправляет код. Всё работает локально.

## Что делает

| Что | Как |
|---|---|
| 🧩 **Код** | ищет опасные конструкции в Python, JS, TS (Semgrep) |
| 📦 **Зависимости** | находит известные CVE в пакетах (Trivy) |
| ⚙️ **Конфигурация** | проверяет Dockerfile, Kubernetes, Terraform (Trivy) |
| 🔑 **Забытые секреты** | находит ключи и токены в файлах проекта, значения не выводит |
| 🧾 **Единый отчёт** | сводит находки всех сканеров в один список с приоритетом и местом в коде |
| 🗺️ **Поверхность атаки** | находит точки входа, опасные вызовы, проверки доступа и небезопасные настройки, подсказывает, какие файлы читать первыми |
| 🔀 **Ревью изменений** | показывает новые рискованные строки и удалённые проверки в diff или PR |
| ⛓️ **Цепочка поставок** | ловит install-скрипты, зависимости из git и URL, подмену пакетов, инъекции в GitHub Actions и `curl \| sh` |
| 🔁 **Похожие баги** | ищет варианты найденной уязвимости своим Semgrep-правилом или regex |
| ✅ **Разбор находок** | хранит вердикты «настоящая / ложная» с обоснованием и выдаёт отчёт в Markdown и SARIF |
| 🤖 **Агент** | подключается к Claude Code, Codex, Cursor и OpenCode через инструкции и MCP, агент разбирает находки и применяет проверенные исправления |

## Установка

В терминале (Linux, macOS, WSL):

```bash
pipx install seckit        # или uv tool install seckit
cd /путь/к/проекту
seckit init
```

`init` скачивает сканеры Trivy и Semgrep и добавляет инструкции Seckit в AGENTS.md, CLAUDE.md, .claude/skills, .agents/skills и .cursor/rules, не трогая ваш текст. Дальше агент сам знает, как работать с Seckit: попросите его проверить проект.

Чтобы агент не спрашивал разрешение на каждый вызов, разрешите ему команду `seckit`: [Claude Code, Codex, Cursor, OpenCode](docs/setup.md#allow-seckit-in-your-agent).

## Документация

[Установка](docs/setup.md) · [Агенты и MCP](docs/agents.md) · [Сканеры](docs/scanners.md) · [Инструменты аудита](docs/audit-tools.md)

<sub>FSL-1.1-ALv2 · Сканирование не гарантирует, что уязвимостей нет.</sub>
