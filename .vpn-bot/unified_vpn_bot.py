#!/usr/bin/env python3
import http.cookiejar
import json
import os
import sqlite3
import ssl
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from pathlib import Path

STATE_FILE = Path(os.environ['STATE_FILE'])
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PROXY2_SSH = "ssh -i /home/hermes/.hermes/home/.ssh/proxy2_id_ed25519 -o IdentitiesOnly=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile=/tmp/proxy2_known_hosts root@proxy2.arch7tect.org"

COMMANDS = {
    'panel', 'inbounds', 'users', 'status', 'top', 'topday', 'topinbound',
    'user', 'restart', 'digestnow', 'links', 'logs', 'alldigestnow'
}

SERVERS = {
    'local': {
        'key': 'local',
        'name': 'local',
        'title': 'local vpn',
        'prefix': '',
        'panel_base': os.environ['LOCAL_PANEL_BASE'].rstrip('/'),
        'panel_user': os.environ['LOCAL_PANEL_USER'],
        'panel_pass': os.environ['LOCAL_PANEL_PASS'],
        'db_path': '/etc/x-ui/x-ui.db',
        'ssh': None,
        'status_ports': ':(443|2443|8443|2053)\\b',
        'service_units': 'x-ui',
        'docker_grep': '',
        'sni': 'claw.arch7tect.org',
    },
    'proxy2': {
        'key': 'proxy2',
        'name': 'proxy2',
        'title': 'proxy2',
        'prefix': 'p',
        'panel_base': os.environ['PROXY2_PANEL_BASE'].rstrip('/'),
        'panel_user': os.environ['PROXY2_PANEL_USER'],
        'panel_pass': os.environ['PROXY2_PANEL_PASS'],
        'db_path': '/root/3x-ui/db/x-ui.db',
        'ssh': PROXY2_SSH,
        'status_ports': ':(443|6443|8443|45173)\\b',
        'service_units': 'nginx',
        'docker_grep': '3xui_app',
        'sni': 'proxy2.arch7tect.org',
    },
}

DEFAULT_SERVER = 'local'
SERVER_ORDER = ['local', 'proxy2']
PREFIX_MAP = {cfg['prefix']: key for key, cfg in SERVERS.items() if cfg['prefix']}
SORTED_PREFIXES = sorted(PREFIX_MAP.keys(), key=len, reverse=True)


def fmt_bytes(n):
    try:
        n = float(n)
    except Exception:
        return str(n)
    units = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    while n >= 1024 and i < len(units) - 1:
        n /= 1024.0
        i += 1
    return f'{n:.2f} {units[i]}'


def get_offset():
    try:
        return json.loads(STATE_FILE.read_text()).get('offset', 0)
    except Exception:
        return 0


def set_offset(offset):
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({'offset': offset}))


def tg_api(method, data=None):
    token = os.environ['BOT_TOKEN']
    url = f'https://api.telegram.org/bot{token}/{method}'
    body = None
    headers = {}
    if data is not None:
        body = urllib.parse.urlencode({k: str(v) for k, v in data.items()}).encode()
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
    req = urllib.request.Request(url, data=body, headers=headers)
    with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
        return json.loads(r.read().decode())


def send(chat_id, text):
    return tg_api('sendMessage', {
        'chat_id': chat_id,
        'text': text,
        'disable_web_page_preview': 'true',
    })


def run_local(cmd, timeout=60):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, timeout=timeout).stdout.strip()


def run_remote(ssh_cmd, payload_cmd, timeout=60):
    full = f"{ssh_cmd} {json.dumps(payload_cmd)}"
    return subprocess.run(full, shell=True, text=True, capture_output=True, timeout=timeout).stdout.strip()


def run_remote_python(ssh_cmd, py_code, timeout=60):
    cmd = f"{ssh_cmd} python3 -"
    return subprocess.run(cmd, shell=True, text=True, input=py_code, capture_output=True, timeout=timeout).stdout.strip()


def panel_login_and_inbounds(cfg):
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        urllib.request.HTTPCookieProcessor(cj),
        urllib.request.HTTPSHandler(context=CTX),
    )
    req = urllib.request.Request(
        cfg['panel_base'] + '/login',
        data=json.dumps({'username': cfg['panel_user'], 'password': cfg['panel_pass']}).encode(),
        headers={'Content-Type': 'application/json'},
    )
    with opener.open(req, timeout=20) as r:
        _ = r.read()
    with opener.open(cfg['panel_base'] + '/panel/api/inbounds/list', timeout=20) as r:
        return json.loads(r.read().decode())['obj']


def top_traffic(rows):
    items = []
    for r in rows:
        for c in r.get('clientStats', []) or []:
            total = (c.get('up') or 0) + (c.get('down') or 0)
            items.append({
                'email': c.get('email', '?'),
                'remark': r.get('remark') or f"{r.get('protocol')}-{r.get('port')}",
                'up': c.get('up') or 0,
                'down': c.get('down') or 0,
                'total': total,
                'subId': c.get('subId', ''),
            })
    items.sort(key=lambda x: x['total'], reverse=True)
    return items[:10]


def top_inbounds(rows):
    items = []
    for r in rows:
        items.append({
            'remark': r.get('remark') or f"{r.get('protocol')}-{r.get('port')}",
            'protocol': r.get('protocol'),
            'port': r.get('port'),
            'up': r.get('up') or 0,
            'down': r.get('down') or 0,
            'total': (r.get('up') or 0) + (r.get('down') or 0),
        })
    items.sort(key=lambda x: x['total'], reverse=True)
    return items


def user_details(rows, name):
    needle = name.lower()
    out = []
    for r in rows:
        for c in r.get('clientStats', []) or []:
            if c.get('email', '').lower() == needle:
                out.append({
                    'email': c.get('email'),
                    'remark': r.get('remark') or f"{r.get('protocol')}-{r.get('port')}",
                    'up': c.get('up') or 0,
                    'down': c.get('down') or 0,
                    'total': (c.get('up') or 0) + (c.get('down') or 0),
                    'enable': c.get('enable'),
                    'subId': c.get('subId', ''),
                })
    return out


def usage_by_day_local(db_path, day_expr="date('now')"):
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    rows = []
    try:
        rows = cur.execute(
            f"select email, sum(ifnull(up,0)), sum(ifnull(down,0)), inbound_id from client_traffics where date = {day_expr} group by email, inbound_id order by (sum(ifnull(up,0))+sum(ifnull(down,0))) desc"
        ).fetchall()
    except Exception:
        rows = []
    id_to_remark = {r[0]: (r[1] or f'inbound-{r[0]}') for r in cur.execute("select id, remark from inbounds")}
    con.close()
    return [
        {
            'email': e,
            'up': u or 0,
            'down': d or 0,
            'total': (u or 0) + (d or 0),
            'remark': id_to_remark.get(iid, f'inbound-{iid}'),
        }
        for e, u, d, iid in rows
    ]


def usage_by_day_remote(cfg, day_expr="date('now')"):
    py = f'''
import sqlite3, json
con=sqlite3.connect({cfg['db_path']!r})
cur=con.cursor()
rows=[]
try:
    rows=cur.execute("select email, sum(ifnull(up,0)), sum(ifnull(down,0)), inbound_id from client_traffics where date = {day_expr} group by email, inbound_id order by (sum(ifnull(up,0))+sum(ifnull(down,0))) desc").fetchall()
except Exception:
    rows=[]
id_to_remark={{r[0]:(r[1] or f'inbound-{{r[0]}}') for r in cur.execute("select id, remark from inbounds")}}
out=[{{'email':e,'up':u or 0,'down':d or 0,'total':(u or 0)+(d or 0),'remark':id_to_remark.get(iid,f'inbound-{{iid}}')}} for e,u,d,iid in rows]
print(json.dumps(out))
'''
    out = run_remote_python(cfg['ssh'], py, timeout=60)
    return json.loads(out) if out else []


def topday_local(db_path):
    rows = usage_by_day_local(db_path, "date('now')")
    return sorted(rows, key=lambda x: x['total'], reverse=True)[:10]


def topday_remote(cfg):
    rows = usage_by_day_remote(cfg, "date('now')")
    return sorted(rows, key=lambda x: x['total'], reverse=True)[:10]


def usage_yesterday(cfg):
    day_expr = "date('now','-1 day')"
    rows = usage_by_day_remote(cfg, day_expr) if cfg['ssh'] else usage_by_day_local(cfg['db_path'], day_expr)
    merged = {}
    for x in rows:
        item = merged.setdefault(x['email'], {'email': x['email'], 'yesterday': 0, 'remarks': set()})
        item['yesterday'] += x['total']
        if x.get('remark'):
            item['remarks'].add(x['remark'])
    return merged


def totals_from_panel(rows):
    merged = {}
    for r in rows:
        remark = r.get('remark') or f"{r.get('protocol')}-{r.get('port')}"
        for c in r.get('clientStats', []) or []:
            email = c.get('email', '?')
            item = merged.setdefault(email, {'email': email, 'total': 0, 'remarks': set()})
            item['total'] += (c.get('up') or 0) + (c.get('down') or 0)
            item['remarks'].add(remark)
    return merged


def combined_user_usage(cfg, rows):
    totals = totals_from_panel(rows)
    yesterday = usage_yesterday(cfg)
    emails = sorted(set(totals) | set(yesterday))
    combined = []
    for email in emails:
        total = totals.get(email, {}).get('total', 0)
        yday = yesterday.get(email, {}).get('yesterday', 0)
        remarks = set()
        remarks |= totals.get(email, {}).get('remarks', set())
        remarks |= yesterday.get(email, {}).get('remarks', set())
        combined.append({
            'email': email,
            'yesterday': yday,
            'total': total,
            'remarks': sorted(remarks),
        })
    combined.sort(key=lambda x: (x['yesterday'], x['total']), reverse=True)
    return combined


def server_health(cfg):
    problems = []
    if cfg['ssh']:
        active = run_remote(cfg['ssh'], f"systemctl is-active {cfg['service_units']} | cat")
        if active.strip() != 'active':
            problems.append(f"service={active.strip() or 'unknown'}")
        if cfg['docker_grep']:
            docker = run_remote(cfg['ssh'], f"docker ps --format '{{{{.Names}}}} {{{{.Status}}}}' | grep {cfg['docker_grep']} || true")
            if not docker.strip():
                problems.append('docker app not running')
    else:
        active = run_local(f"systemctl is-active {cfg['service_units']} | cat")
        if active.strip() != 'active':
            problems.append(f"service={active.strip() or 'unknown'}")

    try:
        rows = panel_login_and_inbounds(cfg)
        enabled = sum(1 for r in rows if r.get('enable'))
        return {
            'ok': not problems,
            'problems': problems,
            'rows': rows,
            'enabled': enabled,
        }
    except Exception as e:
        problems.append(f"panel api: {type(e).__name__}")
        return {
            'ok': False,
            'problems': problems,
            'rows': [],
            'enabled': 0,
        }


def digest_now(cfg):
    health = server_health(cfg)
    rows = health['rows']
    users = combined_user_usage(cfg, rows) if rows else []
    status_emoji = '✅' if health['ok'] else '❌'
    status_text = 'всё работает' if health['ok'] else ('проблема: ' + '; '.join(health['problems']))
    lines = [
        f"{status_emoji} {cfg['title']}",
        f"Статус: {status_text}",
        f"Активных inbound'ов: {health['enabled']}",
    ]
    if not users:
        lines.append('Пользователи: данных пока нет')
        return '\n'.join(lines)

    lines.append('Пользователи:')
    for i, x in enumerate(users[:10], 1):
        parts = []
        if x['yesterday'] > 0:
            parts.append(f"вчера {fmt_bytes(x['yesterday'])}")
        else:
            parts.append('вчера 0 B')
        parts.append(f"всего {fmt_bytes(x['total'])}")
        if x['remarks']:
            parts.append(', '.join(x['remarks'][:2]))
        lines.append(f"{i}. {x['email']} — {' | '.join(parts)}")
    if len(users) > 10:
        lines.append(f"… и ещё {len(users) - 10} пользователей")
    return '\n'.join(lines)


def digest_all():
    blocks = ['Сводка по VPN:']
    for key in SERVER_ORDER:
        blocks.append(digest_now(SERVERS[key]))
    return '\n\n'.join(blocks)


def get_links(rows, sni_hint):
    out = []
    for r in rows:
        if r.get('protocol') == 'vless':
            for c in r.get('clientStats', []) or []:
                out.append(f"VLESS {c.get('email')}: subId {c.get('subId', '-')} | inbound {r.get('remark')}")
        elif r.get('protocol') == 'hysteria':
            try:
                settings = json.loads(r.get('settings') or '{}')
            except Exception:
                settings = {}
            for c in settings.get('clients', []):
                out.append(f"HY2 {c.get('email')}: auth {c.get('auth', '-')} | port {r.get('port')} | sni {sni_hint}")
    return out[:20]


def status_text(cfg):
    if cfg['ssh']:
        active = run_remote(cfg['ssh'], f"systemctl is-active {cfg['service_units']} | cat")
        ports = run_remote(cfg['ssh'], f"ss -tulpn | egrep '{cfg['status_ports']}' || true")
        docker = run_remote(cfg['ssh'], f"docker ps --format '{{{{.Names}}}} {{{{.Status}}}}' | grep {cfg['docker_grep']} || true")
    else:
        active = run_local(f"systemctl is-active {cfg['service_units']} | cat")
        ports = run_local(f"ss -tulpn | egrep '{cfg['status_ports']}' || true")
        docker = ''
    return f"services:\n{active}\n{docker}\n\nPorts:\n{ports}"


def restart_service(cfg):
    if cfg['ssh']:
        return run_remote(cfg['ssh'], "cd /root/3x-ui && docker compose restart && sleep 3 && docker ps --format '{{.Names}} {{.Status}}' | grep 3xui_app || true", timeout=180)
    return run_local("systemctl restart x-ui && sleep 3 && systemctl is-active x-ui | cat", timeout=120)


def logs_text(cfg):
    if cfg['ssh']:
        return run_remote(cfg['ssh'], "journalctl -u nginx -n 40 --no-pager 2>/dev/null | tail -n 30", timeout=60)
    return run_local("journalctl -u x-ui -n 40 --no-pager 2>/dev/null | tail -n 30", timeout=60)


def format_help_command(cfg, cmd):
    prefix = cfg['prefix']
    return f"/{prefix}{cmd}" if prefix else f"/{cmd}"


def server_help_lines(cfg):
    cmds = [
        'panel', 'inbounds', 'users', 'status', 'top', 'topday',
        'topinbound', 'user <name>', 'restart', 'digestnow', 'links', 'logs'
    ]
    rendered = []
    for cmd in cmds:
        if ' ' in cmd:
            base, rest = cmd.split(' ', 1)
            rendered.append(f"{format_help_command(cfg, base)} {rest}")
        else:
            rendered.append(format_help_command(cfg, cmd))
    return rendered


def help_text():
    lines = [
        'Unified VPN bot',
        '',
        'default (local vpn):',
        ' '.join(server_help_lines(SERVERS['local'])),
        '',
        'remote prefixes:',
        f"p = {SERVERS['proxy2']['title']}",
        ' '.join(server_help_lines(SERVERS['proxy2'])),
        '',
        'global:',
        '/alldigestnow',
    ]
    return '\n'.join(lines)


def parse_command(text):
    raw = text.strip().split(maxsplit=1)
    token = raw[0].lower()
    arg = raw[1].strip() if len(raw) > 1 else ''
    if not token.startswith('/'):
        return SERVERS[DEFAULT_SERVER], token, arg

    cmd = token[1:]
    if cmd == 'alldigestnow':
        return None, cmd, arg

    if cmd in COMMANDS:
        return SERVERS[DEFAULT_SERVER], cmd, arg

    for prefix in SORTED_PREFIXES:
        if cmd.startswith(prefix):
            candidate = cmd[len(prefix):]
            if candidate in COMMANDS:
                return SERVERS[PREFIX_MAP[prefix]], candidate, arg

    return SERVERS[DEFAULT_SERVER], cmd, arg


def command_set(chat_id, cfg, cmd, arg=''):
    if cmd == 'alldigestnow':
        send(chat_id, digest_all())
    elif cmd == 'panel':
        send(chat_id, f"Panel: {cfg['panel_base']}/\nUser: {cfg['panel_user']}")
    elif cmd == 'inbounds':
        rows = panel_login_and_inbounds(cfg)
        lines = [f"- {r.get('remark') or '(no remark)'} | {r['protocol']} | {r['port']} | {'on' if r['enable'] else 'off'}" for r in rows]
        send(chat_id, 'Inbounds:\n' + '\n'.join(lines))
    elif cmd == 'users':
        rows = panel_login_and_inbounds(cfg)
        chunks = []
        for r in rows:
            clients = []
            try:
                settings = json.loads(r.get('settings') or '{}')
            except Exception:
                settings = {}
            for c in settings.get('clients', []):
                clients.append(c.get('email', '?'))
            chunks.append(f"{r.get('remark') or r['protocol']+'-'+str(r['port'])}: {', '.join(clients) if clients else '-'}")
        send(chat_id, 'Users:\n' + '\n'.join(chunks))
    elif cmd == 'status':
        send(chat_id, status_text(cfg))
    elif cmd == 'top':
        rows = panel_login_and_inbounds(cfg)
        top = top_traffic(rows)
        if not top:
            send(chat_id, 'No client traffic stats found.')
        else:
            lines = ['Top traffic consumers:']
            for i, x in enumerate(top, 1):
                lines.append(f"{i}. {x['email']} | {x['remark']} | total {fmt_bytes(x['total'])} | down {fmt_bytes(x['down'])} | up {fmt_bytes(x['up'])}")
            send(chat_id, '\n'.join(lines))
    elif cmd == 'topinbound':
        rows = panel_login_and_inbounds(cfg)
        top = top_inbounds(rows)
        lines = ['Inbound traffic:']
        for i, x in enumerate(top, 1):
            lines.append(f"{i}. {x['remark']} | {x['protocol']}:{x['port']} | total {fmt_bytes(x['total'])} | down {fmt_bytes(x['down'])} | up {fmt_bytes(x['up'])}")
        send(chat_id, '\n'.join(lines))
    elif cmd == 'topday':
        rows = topday_remote(cfg) if cfg['ssh'] else topday_local(cfg['db_path'])
        if not rows:
            send(chat_id, 'No daily traffic data found.')
        else:
            lines = ['Top traffic today:']
            for i, x in enumerate(rows, 1):
                lines.append(f"{i}. {x['email']} | {x['remark']} | total {fmt_bytes(x['total'])} | down {fmt_bytes(x['down'])} | up {fmt_bytes(x['up'])}")
            send(chat_id, '\n'.join(lines))
    elif cmd == 'user':
        if not arg:
            send(chat_id, f"Usage: {format_help_command(cfg, 'user')} <name>")
        else:
            rows = panel_login_and_inbounds(cfg)
            matches = user_details(rows, arg)
            if not matches:
                send(chat_id, f'User not found: {arg}')
            else:
                lines = [f"User {arg}:"]
                for x in matches:
                    lines.append(f"- {x['remark']} | total {fmt_bytes(x['total'])} | down {fmt_bytes(x['down'])} | up {fmt_bytes(x['up'])} | enabled {x['enable']} | subId {x['subId'] or '-'}")
                send(chat_id, '\n'.join(lines))
    elif cmd == 'restart':
        send(chat_id, f"Restarting {cfg['title']}...")
        out = restart_service(cfg)
        send(chat_id, f'Restart done.\n{out}')
    elif cmd == 'digestnow':
        send(chat_id, digest_now(cfg))
    elif cmd == 'links':
        rows = panel_login_and_inbounds(cfg)
        send(chat_id, 'Links / identifiers:\n' + ('\n'.join(get_links(rows, cfg['sni'])) or 'no data'))
    elif cmd == 'logs':
        send(chat_id, 'Recent logs:\n' + (logs_text(cfg) or 'no logs'))
    else:
        send(chat_id, f'Unknown command: {cmd}\n\n' + help_text())


def main_loop():
    offset = get_offset()
    admin_chat = os.environ['ADMIN_CHAT_ID']
    while True:
        try:
            res = tg_api('getUpdates', {'timeout': 30, 'offset': offset})
            for upd in res.get('result', []):
                offset = max(offset, upd['update_id'] + 1)
                msg = upd.get('message') or upd.get('edited_message')
                if not msg:
                    continue
                text = msg.get('text', '')
                if not text.startswith('/'):
                    continue
                chat_id = str(msg['chat']['id'])
                if chat_id != admin_chat:
                    send(chat_id, 'Unauthorized.')
                    set_offset(offset)
                    continue
                if text.strip().split()[0].lower() in ['/start', '/help']:
                    send(chat_id, help_text())
                    set_offset(offset)
                    continue
                cfg, cmd, arg = parse_command(text)
                command_set(chat_id, cfg, cmd, arg)
                set_offset(offset)
        except Exception as e:
            try:
                send(admin_chat, f'unified vpn bot error: {type(e).__name__}: {e}')
            except Exception:
                pass
            time.sleep(5)


def main():
    if len(sys.argv) > 1 and sys.argv[1] == '--digest-all':
        print(digest_all())
        return
    if len(sys.argv) > 1 and sys.argv[1] == '--digest-one':
        key = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_SERVER
        print(digest_now(SERVERS[key]))
        return
    main_loop()


if __name__ == '__main__':
    main()
