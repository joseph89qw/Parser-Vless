#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP/HTTPS Source Loader
============================================
- Читает источники из sources.txt
- Скачивает в THREADS потоков (asyncio + aiohttp)
- Извлекает конфиги vless://, trojan://, hy2:// из текста, base64, JSON (Xray outbounds), YAML (Sing-box/Clash)
- При неудаче обычного GET использует резервный Happ-метод (HWID, спец. User-Agent)
- Источник сохраняется, если найден хотя бы один конфиг
- Неудачные источники -> blacklist_sources.txt и удаление из sources.txt
- Добавляет свои конфиги из my_configs.txt (перед загрузкой)
- Выводит прогресс в реальном времени
"""

import asyncio
import aiohttp
import aiofiles
import os
import re
import sys
import json
import yaml
import base64
import urllib.parse
import time
from pathlib import Path
from typing import Set, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor
import requests

# ========= Конфигурация =========
SOURCES_FILE = "sources.txt"
CONFIGS_FILE = "configs.txt"
MY_CONFIGS_FILE = "my_configs.txt"
BLACKLIST_FILE = "blacklist_sources.txt"

THREADS = 50
TIMEOUT_NORMAL = 5
TIMEOUT_HAPP = 5
USER_AGENT_DEFAULT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Для Happ-метода
HWID_STATIC = "d060e73eb61d1ba7"
HAPP_USER_AGENTS = [
    "Happ/3.18.3/Android/17771400994551771562",
]

# ========= Регулярные выражения =========
VLESS_REGEX = re.compile(r"vless://[^\s#]+", re.IGNORECASE)
TROJAN_REGEX = re.compile(r"trojan://[^\s#]+", re.IGNORECASE)
HY2_REGEX = re.compile(r"(?:hysteria2|hy2)://[^\s#]+", re.IGNORECASE)
URL_REGEX = re.compile(r'https?://[^\s<>"\'(){}|\\^`\[\]]+', re.IGNORECASE)
BASE64_REGEX = re.compile(r'^[A-Za-z0-9+/]+=*$', re.MULTILINE)
UUID_REGEX = re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}')

# ========= Вспомогательные функции =========
def clean_text(text: str) -> str:
    if not text:
        return ""
    text = text.replace('\ufeff', '').replace('\u200b', '')
    return text

def is_valid_config(url: str) -> bool:
    url = url.strip()
    if url.startswith("vless://"):
        return "@" in url and UUID_REGEX.search(url)
    if url.startswith("trojan://"):
        return "@" in url
    if url.startswith(("hysteria2://", "hy2://")):
        return "@" in url
    return False

# ========= Конвертеры JSON/YAML (полные версии) =========
def safe_quote(s: str) -> str:
    return urllib.parse.quote(s, safe='')

def build_query(params: dict) -> str:
    parts = []
    for k, v in params.items():
        if v is None or v == '':
            continue
        if isinstance(v, bool):
            v = 'true' if v else 'false'
        parts.append(f"{k}={safe_quote(str(v))}")
    return '&'.join(parts)

def outbound_to_vless_url(out: dict) -> Optional[str]:
    settings = out.get('settings', {})
    vnext = settings.get('vnext', [])
    if not vnext:
        return None
    first = vnext[0]
    address = first.get('address')
    port = first.get('port')
    users = first.get('users', [])
    if not users:
        return None
    user = users[0]
    uuid = user.get('id')
    if not uuid:
        return None
    encryption = user.get('encryption', 'none')
    flow = user.get('flow', '')
    stream = out.get('streamSettings', {})
    network = stream.get('network', 'tcp')
    security = stream.get('security', '')
    reality = stream.get('realitySettings', {})
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    http = stream.get('httpSettings', {})
    params = {}
    if encryption:
        params['encryption'] = encryption
    if network:
        params['type'] = network
    if flow:
        params['flow'] = flow
    if security == 'reality':
        params['security'] = 'reality'
        if 'serverName' in reality:
            params['sni'] = reality['serverName']
        if 'publicKey' in reality:
            params['pbk'] = reality['publicKey']
        if 'shortId' in reality:
            params['sid'] = reality['shortId']
        if 'fingerprint' in reality:
            params['fp'] = reality['fingerprint']
    elif security == 'tls':
        params['security'] = 'tls'
        if 'serverName' in tls:
            params['sni'] = tls['serverName']
        if 'allowInsecure' in tls:
            params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if 'fingerprint' in tls:
            params['fp'] = tls['fingerprint']
        if 'alpn' in tls:
            params['alpn'] = ','.join(tls['alpn'])
    if network == 'ws' and ws:
        if 'path' in ws:
            params['path'] = safe_quote(ws['path'])
        if 'headers' in ws and 'Host' in ws['headers']:
            params['host'] = ws['headers']['Host']
    elif network == 'grpc' and grpc:
        if 'serviceName' in grpc:
            params['serviceName'] = safe_quote(grpc['serviceName'])
    elif network in ('xhttp', 'splithttp') and 'xhttpSettings' in stream:
        xhttp = stream.get('xhttpSettings', {})
        if 'path' in xhttp:
            params['path'] = safe_quote(xhttp['path'])
        if 'host' in xhttp:
            params['host'] = xhttp['host']
    elif network in ('h2', 'http2') and http:
        if 'path' in http:
            params['path'] = safe_quote(http['path'])
        if 'host' in http:
            params['host'] = ','.join(http['host']) if isinstance(http['host'], list) else http['host']
    if params.get('security') == 'reality':
        if 'alpn' not in params:
            params['alpn'] = urllib.parse.quote('http/1.1')
    params = {k: v for k, v in params.items() if v not in (None, '')}
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    return f"vless://{uuid}@{address}:{port}?{query}{remark}"

def outbound_to_trojan_url(out: dict) -> Optional[str]:
    settings = out.get('settings', {})
    servers = settings.get('servers', [])
    if not servers:
        return None
    s = servers[0]
    address = s.get('address')
    port = s.get('port')
    password = s.get('password')
    if not all([address, port, password]):
        return None
    stream = out.get('streamSettings', {})
    security = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    ws = stream.get('wsSettings', {})
    grpc = stream.get('grpcSettings', {})
    params = {}
    if security == 'tls':
        if 'serverName' in tls:
            params['sni'] = tls['serverName']
        if 'allowInsecure' in tls:
            params['allowInsecure'] = '1' if tls['allowInsecure'] else '0'
        if 'fingerprint' in tls:
            params['fp'] = tls['fingerprint']
        if 'alpn' in tls:
            params['alpn'] = ','.join(tls['alpn'])
    network = stream.get('network', 'tcp')
    if network != 'tcp':
        params['type'] = network
        if network == 'ws' and ws:
            if 'path' in ws:
                params['path'] = safe_quote(ws['path'])
            if 'headers' in ws and 'Host' in ws['headers']:
                params['host'] = ws['headers']['Host']
        elif network == 'grpc' and grpc:
            if 'serviceName' in grpc:
                params['serviceName'] = safe_quote(grpc['serviceName'])
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    base = f"trojan://{password}@{address}:{port}"
    if query:
        base += f"?{query}"
    return base + remark

def outbound_to_hysteria2_url(out: dict) -> Optional[str]:
    settings = out.get('settings', {})
    servers = settings.get('servers', [])
    if not servers:
        return None
    s = servers[0]
    address = s.get('address')
    port = s.get('port')
    auth = s.get('auth', '')
    if not address or not port:
        return None
    stream = out.get('streamSettings', {})
    security = stream.get('security', 'tls')
    tls = stream.get('tlsSettings', {})
    params = {}
    if security == 'tls':
        if 'serverName' in tls:
            params['sni'] = tls['serverName']
        if 'allowInsecure' in tls:
            params['insecure'] = '1' if tls['allowInsecure'] else '0'
        if 'alpn' in tls:
            params['alpn'] = ','.join(tls['alpn'])
    transport = stream.get('transport', {})
    if 'hopConfig' in transport:
        hop = transport['hopConfig']
        if hop.get('obfs') == 'salamander' and hop.get('password'):
            params['obfs-password'] = hop['password']
            params['obfs'] = 'salamander'
    query = build_query(params)
    remark = out.get('tag', '')
    remark = f"#{safe_quote(remark)}" if remark else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{address}:{port}?{query}{remark}"

def yaml_proxy_to_vless_url(proxy: dict) -> Optional[str]:
    name = proxy.get('name', '')
    server = proxy.get('server')
    port = proxy.get('port')
    uuid = proxy.get('uuid')
    if not all([server, port, uuid]):
        return None
    params = {'encryption': 'none', 'type': proxy.get('network', 'tcp')}
    if proxy.get('flow'):
        params['flow'] = proxy['flow']
    tls = proxy.get('tls', False)
    reality_opts = proxy.get('reality-opts', {})
    if reality_opts:
        params['security'] = 'reality'
        if 'public-key' in reality_opts:
            params['pbk'] = reality_opts['public-key']
        if 'short-id' in reality_opts and reality_opts['short-id']:
            params['sid'] = reality_opts['short-id']
    elif tls:
        params['security'] = 'tls'
    sni = proxy.get('servername')
    if sni:
        params['sni'] = sni
    fp = proxy.get('client-fingerprint')
    if fp:
        params['fp'] = fp
    network = proxy.get('network', 'tcp')
    if network == 'grpc':
        grpc_opts = proxy.get('grpc-opts', {})
        if 'grpc-service-name' in grpc_opts:
            params['serviceName'] = grpc_opts['grpc-service-name']
    elif network in ('ws', 'websocket'):
        ws_opts = proxy.get('ws-opts', {})
        if 'path' in ws_opts:
            params['path'] = safe_quote(ws_opts['path'])
        if 'headers' in ws_opts and 'Host' in ws_opts['headers']:
            params['host'] = ws_opts['headers']['Host']
    if params.get('security') == 'reality':
        if 'alpn' not in params:
            params['alpn'] = urllib.parse.quote('http/1.1')
    params = {k: v for k, v in params.items() if v not in (None, '')}
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    return f"vless://{uuid}@{server}:{port}?{query}{remark}"

def yaml_proxy_to_trojan_url(proxy: dict) -> Optional[str]:
    name = proxy.get('name', '')
    server = proxy.get('server')
    port = proxy.get('port')
    password = proxy.get('password')
    if not all([server, port, password]):
        return None
    params = {}
    sni = proxy.get('servername')
    if sni:
        params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls:
        params['security'] = 'tls'
    fp = proxy.get('client-fingerprint')
    if fp:
        params['fp'] = fp
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    base = f"trojan://{password}@{server}:{port}"
    if query:
        base += f"?{query}"
    return base + remark

def yaml_proxy_to_hysteria2_url(proxy: dict) -> Optional[str]:
    name = proxy.get('name', '')
    server = proxy.get('server')
    port = proxy.get('port')
    auth = proxy.get('auth', '')
    if not all([server, port]):
        return None
    params = {}
    sni = proxy.get('servername')
    if sni:
        params['sni'] = sni
    tls = proxy.get('tls', False)
    if tls:
        params['insecure'] = '0'
    query = build_query(params)
    remark = f"#{safe_quote(name)}" if name else ''
    auth_part = f"{auth}@" if auth else ''
    return f"hy2://{auth_part}{server}:{port}?{query}{remark}"

def convert_json_to_urls(content: str) -> List[str]:
    urls = []
    try:
        decoder = json.JSONDecoder()
        idx = 0
        content = content.strip()
        while idx < len(content):
            try:
                obj, end = decoder.raw_decode(content, idx)
                idx = end
                while idx < len(content) and content[idx] in ' \t\n\r':
                    idx += 1
                outbounds = None
                if isinstance(obj, dict):
                    outbounds = obj.get('outbounds')
                    if outbounds is None and 'config' in obj:
                        outbounds = obj['config'].get('outbounds')
                elif isinstance(obj, list):
                    outbounds = obj
                if not outbounds or not isinstance(outbounds, list):
                    continue
                for out in outbounds:
                    if not isinstance(out, dict):
                        continue
                    protocol = out.get('protocol', '')
                    if protocol == 'vless':
                        url = outbound_to_vless_url(out)
                        if url and is_valid_config(url):
                            urls.append(url)
                    elif protocol == 'trojan':
                        url = outbound_to_trojan_url(out)
                        if url and is_valid_config(url):
                            urls.append(url)
                    elif protocol in ('hysteria2', 'hy2'):
                        url = outbound_to_hysteria2_url(out)
                        if url and is_valid_config(url):
                            urls.append(url)
            except json.JSONDecodeError:
                break
    except Exception:
        pass
    return urls

def convert_yaml_to_urls(content: str) -> List[str]:
    urls = []
    try:
        data = yaml.safe_load(content)
        if not data or not isinstance(data, dict):
            return []
        proxies = data.get('proxies', [])
        if not isinstance(proxies, list):
            return []
        for proxy in proxies:
            ptype = proxy.get('type')
            if ptype == 'vless':
                url = yaml_proxy_to_vless_url(proxy)
            elif ptype == 'trojan':
                url = yaml_proxy_to_trojan_url(proxy)
            elif ptype in ('hysteria2', 'hy2'):
                url = yaml_proxy_to_hysteria2_url(proxy)
            else:
                continue
            if url and is_valid_config(url):
                urls.append(url)
    except Exception:
        pass
    return urls

def decode_base64_content(content: str) -> Tuple[Optional[str], List[str]]:
    try:
        content = content.strip()
        if not BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
            return None, []
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        matches = []
        matches.extend(VLESS_REGEX.findall(decoded))
        matches.extend(TROJAN_REGEX.findall(decoded))
        matches.extend(HY2_REGEX.findall(decoded))
        if len(decoded) > 100 and BASE64_REGEX.match(decoded.replace('\n', '').replace('\r', '')):
            deeper = decode_base64_content(decoded)
            if deeper[1]:
                matches.extend(deeper[1])
        return decoded, matches
    except:
        return None, []

def extract_configs_from_text(text: str) -> Tuple[List[str], List[str], List[str], int, int, int]:
    """
    Извлекает конфиги из текста.
    Возвращает (vless_list, trojan_list, hy2_list, base64_count, json_count, yaml_count)
    Теперь возвращаем списки (с дублями), а не множества.
    """
    vless_list = []
    trojan_list = []
    hy2_list = []
    base64_count = 0
    json_count = 0
    yaml_count = 0

    # Прямой поиск
    for v in VLESS_REGEX.findall(text):
        vless_list.append(v)
    for t in TROJAN_REGEX.findall(text):
        trojan_list.append(t)
    for h in HY2_REGEX.findall(text):
        hy2_list.append(h)

    # Base64
    b64_res = decode_base64_content(text)
    if b64_res[1]:
        base64_count = 1
        for m in b64_res[1]:
            if m.startswith("vless://"):
                vless_list.append(m)
            elif m.startswith("trojan://"):
                trojan_list.append(m)
            elif m.startswith(("hysteria2://", "hy2://")):
                hy2_list.append(m)

    # JSON
    if text.strip().startswith(('{', '[')):
        json_urls = convert_json_to_urls(text)
        if json_urls:
            json_count = 1
            for u in json_urls:
                if u.startswith("vless://"):
                    vless_list.append(u)
                elif u.startswith("trojan://"):
                    trojan_list.append(u)
                elif u.startswith(("hysteria2://", "hy2://")):
                    hy2_list.append(u)

    # YAML (Sing-box / Clash)
    if 'proxies:' in text or 'type: vless' in text.lower():
        yaml_urls = convert_yaml_to_urls(text)
        if yaml_urls:
            yaml_count = 1
            for u in yaml_urls:
                if u.startswith("vless://"):
                    vless_list.append(u)
                elif u.startswith("trojan://"):
                    trojan_list.append(u)
                elif u.startswith(("hysteria2://", "hy2://")):
                    hy2_list.append(u)

    return vless_list, trojan_list, hy2_list, base64_count, json_count, yaml_count

# ========= Happ-метод (резервный) =========
def fetch_with_happ_method(url: str) -> Optional[str]:
    parsed = urllib.parse.urlparse(url)
    if 'hwid=' not in url:
        separator = '&' if parsed.query else '?'
        url_with_hwid = f"{url}{separator}hwid={HWID_STATIC}"
    else:
        url_with_hwid = url
    for try_url in [url_with_hwid, url]:
        for ua in HAPP_USER_AGENTS:
            try:
                headers = {
                    "User-Agent": ua,
                    "X-HWID": HWID_STATIC,
                    "Accept": "*/*",
                    "Accept-Encoding": "gzip, deflate",
                    "Connection": "keep-alive"
                }
                resp = requests.get(try_url, headers=headers, timeout=TIMEOUT_HAPP)
                resp.raise_for_status()
                content = resp.text.strip()
                if "<html" in content.lower():
                    continue
                if BASE64_REGEX.match(content.replace('\n', '').replace('\r', '')):
                    decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
                    if decoded:
                        content = decoded
                return content
            except Exception:
                continue
    return None

# ========= Основная логика скачивания =========
async def process_source(session: aiohttp.ClientSession, url: str, sem: asyncio.Semaphore, stats: dict, stats_lock: asyncio.Lock):
    async with sem:
        content = None
        used_happ = False

        # Попытка 1: обычный GET
        try:
            async with session.get(url, timeout=TIMEOUT_NORMAL, ssl=False) as resp:
                if resp.status == 200:
                    content = await resp.text()
        except:
            pass

        # Если не удалось или слишком короткий ответ -> Happ-метод
        if content is None or len(content) < 50:
            loop = asyncio.get_event_loop()
            with ThreadPoolExecutor(max_workers=1) as executor:
                content = await loop.run_in_executor(executor, fetch_with_happ_method, url)
            used_happ = True

        if not content or len(content) < 10:
            async with stats_lock:
                stats['failed'].append(url)
            return

        # Извлекаем конфиги (списки с дублями)
        vless_list, trojan_list, hy2_list, b64_cnt, json_cnt, yaml_cnt = extract_configs_from_text(content)
        total_found = len(vless_list) + len(trojan_list) + len(hy2_list)
        if total_found == 0:
            async with stats_lock:
                stats['failed'].append(url)
            return

        # Обновляем статистику и сохраняем все конфиги (включая дубли) в общий буфер
        async with stats_lock:
            stats['processed'] += 1
            stats['vless_count'] += len(vless_list)
            stats['trojan_count'] += len(trojan_list)
            stats['hy2_count'] += len(hy2_list)
            stats['base64'] += b64_cnt
            stats['json'] += json_cnt
            stats['yaml'] += yaml_cnt
            stats['total_configs'] += total_found
            # Добавляем все конфиги в общий список (без дедупликации)
            stats['all_configs'].extend(vless_list)
            stats['all_configs'].extend(trojan_list)
            stats['all_configs'].extend(hy2_list)
            if used_happ:
                stats['happ_success'] += 1

async def load_http_sources():
    print("\n" + "="*60)
    print("Скачивание конфигураций из источников.")
    print("="*60)

    if not os.path.exists(SOURCES_FILE):
        print(f"Файл {SOURCES_FILE} не найден.")
        return

    with open(SOURCES_FILE, 'r', encoding='utf-8') as f:
        sources = [line.strip() for line in f if line.strip() and not line.startswith('#')]

    if not sources:
        print("Нет источников в sources.txt")
        return

    total_sources = len(sources)
    print(f"Источников для обработки: {total_sources}")

    # Загружаем свои конфиги из my_configs.txt (они будут добавлены в конец)
    my_configs = []
    if os.path.exists(MY_CONFIGS_FILE):
        async with aiofiles.open(MY_CONFIGS_FILE, 'r', encoding='utf-8') as f:
            async for line in f:
                cfg = line.strip()
                if cfg and is_valid_config(cfg):
                    my_configs.append(cfg)
        print(f"  Мои конфиги: {len(my_configs)} (будут добавлены в итоговый файл)")

    # Статистика (без дедупликации)
    stats = {
        'processed': 0,
        'total_sources': total_sources,
        'vless_count': 0,
        'trojan_count': 0,
        'hy2_count': 0,
        'base64': 0,
        'json': 0,
        'yaml': 0,
        'total_configs': 0,
        'all_configs': [],        # список всех найденных конфигов (включая дубли)
        'failed': [],
        'happ_success': 0,
        'lock': asyncio.Lock()
    }

    sem = asyncio.Semaphore(THREADS)
    connector = aiohttp.TCPConnector(limit=0, ssl=False)
    async with aiohttp.ClientSession(connector=connector, headers={"User-Agent": USER_AGENT_DEFAULT}) as session:
        tasks = [process_source(session, url, sem, stats, stats['lock']) for url in sources]
        progress_task = asyncio.create_task(display_progress(stats))
        await asyncio.gather(*tasks)
        progress_task.cancel()

    print()  # перевод строки после прогресса
    print("Загрузка источников завершена.")

    # Удаляем неудачные источники из sources.txt и добавляем в blacklist
    if stats['failed']:
        async with aiofiles.open(BLACKLIST_FILE, 'a', encoding='utf-8') as f:
            for bad_url in stats['failed']:
                await f.write(bad_url + '\n')
        remaining = [url for url in sources if url not in stats['failed']]
        async with aiofiles.open(SOURCES_FILE, 'w', encoding='utf-8') as f:
            for url in remaining:
                await f.write(url + '\n')
        print(f"Удалено неудачных источников: {len(stats['failed'])} (добавлены в {BLACKLIST_FILE})")

    # Сохраняем ВСЕ найденные конфиги (включая дубли) в configs.txt
    all_configs = stats['all_configs'] + my_configs
    if all_configs:
        async with aiofiles.open(CONFIGS_FILE, 'a', encoding='utf-8') as f:
            for cfg in all_configs:
                await f.write(cfg + '\n')
        print(f"Добавлено конфигов в {CONFIGS_FILE}: {len(all_configs)} (включая дубликаты)")
    else:
        print("Конфигов не найдено.")

    # Итоговая статистика
    print(f"\n  Обработано источников: {stats['processed']}/{total_sources}")
    print(f"Всего извлечено конфигов: {stats['total_configs']}")
    print(f"VLESS: {stats['vless_count']} | Trojan: {stats['trojan_count']} | Hysteria2: {stats['hy2_count']}")
    print(f"Расшифровано подписок: {stats['base64']+stats['json']+stats['yaml']} (Base64: {stats['base64']}, JSON: {stats['json']}, YAML: {stats['yaml']})")
    print(f"Обработано через Happ: {stats['happ_success']}")
    print(f"Мои конфиги: {len(my_configs)}")
    print(f"Всего конфигов: {len(all_configs)}")

async def display_progress(stats: dict):
    """Отображает прогресс в реальном времени."""
    while True:
        processed = stats['processed']
        total = stats['total_sources']
        percent = (processed / total * 100) if total > 0 else 0
        bar_len = 20
        filled = int(bar_len * processed / total) if total > 0 else 0
        bar = '█' * filled + '░' * (bar_len - filled)
        v = stats['vless_count']
        t = stats['trojan_count']
        h = stats['hy2_count']
        subs = stats['base64'] + stats['json'] + stats['yaml']
        total_cfgs = stats['total_configs']
        happ = stats['happ_success']
        sys.stdout.write(f"\r|{bar}| {percent:.0f}% Скачано: {processed}/{total} | VLESS: {v} | Trojan: {t} | Hysteria2: {h} | Декодировано: {subs} | Happ: {happ} | Всего: {total_cfgs}")
        sys.stdout.flush()
        await asyncio.sleep(0.3)

async def main():
    await load_http_sources()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nОстановлено пользователем")
