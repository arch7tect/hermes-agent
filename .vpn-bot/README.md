# Unified VPN bot

Локальный каталог unified VPN Telegram bot.

## Что хранится в git
- `unified_vpn_bot.py` — основной код бота
- `.gitignore` — защита секретов и runtime-state
- `README.md` — краткая документация по устройству и восстановлению

## Что не хранится в git
- `unified-vpn-bot.env` — секреты и настройки окружения
- `offset.json` — текущий offset Telegram polling
- `__pycache__/`, `*.pyc` — runtime-артефакты

## Назначение
Один Telegram-бот управляет:
- `local` VPN без префикса в командах
- `proxy2` с префиксом `p`

Примеры:
- `/status` — local
- `/pstatus` — proxy2
- `/alldigestnow` — общая сводка по всем VPN

## Service
Systemd unit использует:
- `EnvironmentFile=/home/hermes/hermes-agent/.vpn-bot/unified-vpn-bot.env`
- `ExecStart=/usr/bin/python3 /home/hermes/hermes-agent/.vpn-bot/unified_vpn_bot.py`
- `WorkingDirectory=/home/hermes/hermes-agent/.vpn-bot`

## Восстановление после потери файлов
1. Восстановить `unified_vpn_bot.py` из git.
2. Восстановить `unified-vpn-bot.env` из секретного хранилища или из окружения живого процесса, если сервис ещё запущен.
3. Создать `offset.json` заново, если он потерян.
4. Проверить запуск:
   - `python3 -m py_compile /home/hermes/hermes-agent/.vpn-bot/unified_vpn_bot.py`
   - `sudo systemctl restart unified-vpn-bot.service`
   - `systemctl status unified-vpn-bot.service --no-pager -l`

## Важно
Если выполнить `git clean -fd` в репозитории, tracked-файлы останутся, но локальные секреты и state-файлы вне git могут быть удалены, если не подпадают под ignore-правила. Текущая `.gitignore` в этом каталоге должна защищать их от обычной очистки.
