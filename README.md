<p align="center">
  <img src="assets/hero.svg" alt="Bluekit" width="100%">
</p>

<p align="center">
  <b>Локальная проверка безопасности проекта для Claude Code, Codex и Cursor.</b><br>
  Русский · <a href="README.en.md">English</a>
</p>

<p align="center">
  <img alt="Python 3.10+" src="https://img.shields.io/badge/python-3.10%2B-3776ab?logo=python&logoColor=white">
  <img alt="Linux · macOS · WSL" src="https://img.shields.io/badge/Linux%20·%20macOS%20·%20WSL-0f172a">
  <img alt="Trivy + Semgrep" src="https://img.shields.io/badge/Trivy%20%2B%20Semgrep-10b981">
  <a href="LICENSE"><img alt="FSL-1.1-ALv2" src="https://img.shields.io/badge/license-FSL--1.1--ALv2-64748b"></a>
</p>

Bluekit ищет уязвимости, а ваш агент разбирает находки и исправляет код. Всё работает локально.

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
| 🤖 **Агент** | подключается к Claude Code, Codex и Cursor через инструкции и MCP, агент разбирает находки и применяет проверенные исправления |

## Установка

Скопируйте агенту этот промпт:

```text
Установи Bluekit для этого проекта и подключи его как постоянный security toolkit. Ничего не спрашивай, я заранее разрешаю:
- установить его командой `pipx install bluekit` или `uv tool install bluekit` (пакет называется именно bluekit, не guardkit); если нет ни pipx, ни uv, поставь его в venv в ~/.local/share/bluekit и сделай ссылку ~/.local/bin/bluekit;
- запускать команду `bluekit`, включая `bluekit init`, который скачает сканеры Trivy и Semgrep;
- добавить блоки Bluekit в AGENTS.md, CLAUDE.md, .claude/skills, .agents/skills и .cursor/rules, сохранив мой текст.
Код проекта и тесты не запускай. Затем выполни `bluekit scan --json`, разбери находки и в конце предложи шаги из next_steps.
```

Агент установит Bluekit, просканирует проект и предложит, что делать дальше. Если автоматический режим агента всё же заблокирует `bluekit init`, выполните его сами: `! bluekit init` в Claude Code.

Или вручную (Linux, macOS, WSL):

```bash
pipx install bluekit
cd /путь/к/проекту && bluekit init && bluekit scan --human
```

Пока пакета нет на PyPI, ставьте из репозитория: `pipx install git+https://github.com/nejroseld/bluekit` (нужен доступ к GitHub). Первый запуск скачивает сканеры и базы.

## Документация

[Установка](docs/setup.md) · [Агенты и MCP](docs/agents.md) · [Сканеры](docs/scanners.md) · [Инструменты аудита](docs/audit-tools.md) · [Проверки](docs/validation.md) · [Аудит](docs/security-audit.md)

<sub>FSL-1.1-ALv2 · Сканирование не гарантирует, что уязвимостей нет.</sub>
