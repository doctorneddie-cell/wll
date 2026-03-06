#!/usr/bin/env python3
"""
Скрипт для парсинга.
Разрешается только некоммерческое использование.
(если вы будете продавать конфиги из парсера - это будет нарушение лицензии)
"""

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from github import GithubException
from github import Github, Auth
from datetime import datetime
import concurrent.futures
import urllib.parse
import threading
import ipaddress
import zoneinfo
import requests
import urllib3
import base64
import json
import re
import os

LOGS_BY_FILE: dict[int, list[str]] = defaultdict(list)
_LOG_LOCK = threading.Lock()

def log(message: str):
    """Добавляет сообщение в общий словарь логов потокобезопасно."""
    with _LOG_LOCK:
        LOGS_BY_FILE[0].append(message)

zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

GITHUB_TOKEN = os.environ.get("MY_TOKEN", "")
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "bywarm/wlr")

# Cloud.ru S3 конфигурация
CLOUD_RU_ENDPOINT = os.environ.get("CLOUD_RU_ENDPOINT", "https://s3.cloud.ru/bucket-93b250")
CLOUD_RU_ACCESS_KEY = os.environ.get("CLOUD_RU_ACCESS_KEY", "28a54be8-b238-4edf-8079-7cee88d2ab3c:d103f9e8c17b5d760f0d713ca4af063c")
CLOUD_RU_SECRET_KEY = os.environ.get("CLOUD_RU_SECRET_KEY", "")
CLOUD_RU_BUCKET = os.environ.get("CLOUD_RU_BUCKET", "bucket-93b250")
CLOUD_RU_REGION = os.environ.get("CLOUD_RU_REGION", "ru-central-1")

# GitVerse API конфигурация (только токен в секретах)
GITVERSE_TOKEN = os.environ.get("GITVERSE_TOKEN", "")

if GITVERSE_TOKEN:
    GITVERSE_ENDPOINT = "https://api.gitverse.ru"
    GITVERSE_REPO_OWNER = "bywarm"
    GITVERSE_REPO_NAME = "rser"
    GITVERSE_BRANCH = "master"
else:
    GITVERSE_ENDPOINT = GITVERSE_REPO_OWNER = GITVERSE_REPO_NAME = GITVERSE_BRANCH = ""

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()

try:
    REPO = g.get_repo(REPO_NAME)
except Exception as e:
    log("Ошибка подключения к GitHub: " + str(e)[:100])
    REPO = None

OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "confs")

CONFIG = {
    "output_dir": OUTPUT_DIR,
    "merged_file": "merged.txt",
    "wl_file": "wl.txt",
    "selected_file": "selected.txt",
    "custom_prefix": "",
    "use_date_suffix": False,
    "rotate_folders": False,
}

if CONFIG["rotate_folders"]:
    month = datetime.now().month
    year_short = datetime.now().strftime("%y")
    CONFIG["output_dir_suffix"] = f"_{year_short}{month:02d}"

def get_paths():
    base_dir = CONFIG["output_dir"]
    return {
        "base_dir": base_dir,
        "merged": f"{base_dir}/{CONFIG['merged_file']}",
        "wl": f"{base_dir}/{CONFIG['wl_file']}",
        "selected": f"{base_dir}/{CONFIG['selected_file']}",
        "black": f"{base_dir}/black.txt",
        "gh_pages_merged": "merged.txt",
        "gh_pages_wl": "wl.txt",
    }

PATHS = get_paths()

EXCLUDE_PATTERNS = [
    "rootface-@pwn1337-telegram",
    "01010101",
    "9292929",
    "38388282",
    "star_test1",
    "11111111-1111-1111-1111-111111111111",
    "a0c5e6d9-519e-4fc1-8b51-27188a2452fe",
    "5e9d63d9-0a7c-4af6-a938-c8130dde089a",
    "xxxxxxxxxx1",
]

EXCLUDE_SETTINGS = {
    "case_sensitive": False,
    "log_excluded": True,
    "save_excluded": True,
}

CIDR_NAME_MAPPING = {
    # Original CIDRs (180 entries)
    "5.188.0.0/16": "?",
    "37.18.0.0/16": "?",
    "37.139.0.0/16": "?",
    "45.15.0.0/16": "?",
    "45.129.0.0/16": "?",
    "51.250.0.0/16": "Yandex",
    "51.250.0.0/17": "Yandex",
    "77.88.21.0/24": "Yandex",
    "78.159.0.0/16": "?",
    "78.159.247.0/24": "?",
    "79.174.91.0/24": "REG.RU",
    "79.174.92.0/24": "REG.RU",
    "79.174.93.0/24": "REG.RU",
    "79.174.94.0/24": "REG.RU",
    "79.174.95.0/24": "REG.RU",
    "83.166.0.0/16": "?",
    "84.201.0.0/16": "firstcolo GmbH",
    "84.201.128.0/18": "Yandex",
    "87.250.247.0/24": "Yandex",
    "87.250.250.0/24": "Yandex",
    "87.250.251.0/24": "Yandex",
    "87.250.254.0/24": "Yandex",
    "89.208.0.0/16": "?",
    "89.253.200.0/21": "?",
    "91.219.0.0/16": "?",
    "91.222.239.0/24": "?",
    "95.163.0.0/16": "?",
    "95.163.248.0/22": "?",
    "95.181.182.0/24": "?",
    "103.111.114.0/24": "?",
    "109.120.0.0/16": "?",
    "109.73.201.0/24": "?",
    "130.193.0.0/16": "?",
    "134.17.94.0/24": "?",
    "158.160.0.0/16": "Yandex",
    "176.32.0.0/16": "?",
    "176.108.0.0/16": "?",
    "176.109.0.0/16": "?",
    "176.122.0.0/16": "?",
    "178.154.0.0/16": "Yandex",
    "185.39.206.0/24": "?",
    "185.130.0.0/16": "?",
    "185.141.216.0/24": "?",
    "185.177.0.0/16": "?",
    "185.177.73.0/24": "?",
    "185.241.192.0/22": "?",
    "193.53.0.0/16": "?",
    "212.233.72.0/21": "?",
    "217.12.0.0/16": "?",
    "217.16.0.0/16": "?",
    "217.16.24.0/21": "?",
    "37.9.38.0/24": "?",
    "37.220.166.0/24": "?",
    "77.41.174.0/24": "?",
    "79.126.125.0/24": "?",
    "81.22.206.0/24": "?",
    "81.177.73.0/24": "?",
    "81.211.48.0/24": "?",
    "82.208.79.0/24": "?",
    "82.209.65.0/24": "?",
    "85.26.166.0/24": "?",
    "85.234.38.0/24": "?",
    "89.248.230.0/24": "?",
    "91.233.216.0/24": "?",
    "91.233.217.0/24": "?",
    "91.233.218.0/24": "?",
    "92.223.43.0/24": "?",
    "94.229.232.0/24": "?",
    "95.142.205.0/24": "?",
    "95.163.43.0/24": "?",
    "95.167.222.0/24": "?",
    "95.181.181.0/24": "?",
    "109.120.190.0/24": "?",
    "128.75.235.0/24": "?",
    "128.75.253.0/24": "?",
    "128.140.170.0/24": "?",
    "146.185.209.0/24": "?",
    "151.236.75.0/24": "?",
    "151.236.87.0/24": "?",
    "151.236.90.0/24": "?",
    "151.236.96.0/24": "?",
    "151.236.99.0/24": "?",
    "155.212.192.0/24": "?",
    "176.211.118.0/24": "?",
    "178.176.128.0/24": "?",
    "178.176.145.0/24": "?",
    "178.178.103.0/24": "?",
    "178.237.22.0/24": "?",
    "178.248.232.0/24": "?",
    "178.248.233.0/24": "?",
    "178.248.234.0/24": "?",
    "178.248.235.0/24": "?",
    "178.248.238.0/24": "?",
    "178.248.239.0/24": "?",
    "185.9.230.0/24": "?",
    "185.16.150.0/24": "?",
    "185.27.192.0/24": "?",
    "185.32.187.0/24": "?",
    "185.32.251.0/24": "?",
    "185.45.82.0/24": "?",
    "185.62.201.0/24": "?",
    "185.65.148.0/24": "?",
    "185.65.149.0/24": "?",
    "185.72.228.0/24": "?",
    "185.72.229.0/24": "?",
    "185.72.231.0/24": "?",
    "185.73.192.0/24": "?",
    "185.73.193.0/24": "?",
    "185.73.194.0/24": "?",
    "185.73.195.0/24": "?",
    "185.163.159.0/24": "?",
    "185.226.55.0/24": "?",
    "185.241.193.0/24": "?",
    "185.242.16.0/24": "?",
    "188.43.2.0/24": "?",
    "188.43.3.0/24": "?",
    "188.43.5.0/24": "?",
    "188.170.146.0/24": "?",
    "194.67.49.0/24": "?",
    "194.85.149.0/24": "?",
    "194.154.70.0/24": "?",
    "194.154.71.0/24": "?",
    "194.154.73.0/24": "?",
    "194.154.76.0/24": "?",
    "194.154.80.0/24": "?",
    "194.186.16.0/24": "?",
    "194.186.17.0/24": "?",
    "194.186.26.0/24": "?",
    "194.186.31.0/24": "?",
    "194.186.81.0/24": "?",
    "194.186.86.0/24": "?",
    "194.186.91.0/24": "?",
    "194.186.96.0/24": "?",
    "194.186.158.0/24": "?",
    "194.186.168.0/24": "?",
    "194.186.172.0/24": "?",
    "194.186.174.0/24": "?",
    "194.186.244.0/24": "?",
    "194.186.249.0/24": "?",
    "194.186.250.0/24": "?",
    "195.34.36.0/24": "?",
    "195.34.37.0/24": "?",
    "195.34.38.0/24": "?",
    "195.34.58.0/24": "?",
    "195.239.1.0/24": "?",
    "195.239.7.0/24": "?",
    "195.239.9.0/24": "?",
    "195.239.13.0/24": "?",
    "195.239.38.0/24": "?",
    "195.239.57.0/24": "?",
    "195.239.67.0/24": "?",
    "195.239.68.0/24": "?",
    "195.239.94.0/24": "?",
    "195.239.109.0/24": "?",
    "195.239.156.0/24": "?",
    "195.239.158.0/24": "?",
    "195.239.159.0/24": "?",
    "212.46.197.0/24": "?",
    "212.46.198.0/24": "?",
    "212.46.200.0/24": "?",
    "212.46.208.0/24": "?",
    "212.46.210.0/24": "?",
    "212.46.254.0/24": "?",
    "212.188.4.0/24": "?",
    "212.188.6.0/24": "?",
    "212.188.8.0/24": "?",
    "212.188.12.0/24": "?",
    "212.188.15.0/24": "?",
    "212.188.16.0/24": "?",
    "212.193.146.0/24": "?",
    "212.193.147.0/24": "?",
    "213.87.71.0/24": "?",
    "213.184.156.0/24": "?",
    "217.20.158.0/24": "?",
    "217.118.183.0/24": "?",
    "217.174.188.0/24": "?",
    "80.68.251.0/24": "?",
    "91.208.84.0/24": "?",
    "91.232.131.0/24": "?",
    "109.207.4.0/24": "?",
    "87.240.128.0/19": "VK",
    "87.240.129.0/24": "VK",
    "87.240.132.0/24": "VK",
    "87.240.137.0/24": "VK",
    "87.240.138.0/24": "VK",
    "93.186.224.0/23": "VK",
    "95.213.56.0/24": "VK",
    "31.31.204.0/23": "REG.RU",
    "134.0.116.0/22": "REG.RU",
    "151.248.112.0/24": "REG.RU",
    "178.21.14.0/23": "REG.RU",
    "188.93.208.0/21": "REG.RU",
    "194.58.112.0/23": "REG.RU",
    "194.58.116.0/23": "REG.RU",
    "194.67.72.0/24": "REG.RU",
    "31.41.154.0/23": "Selectel",
    "31.41.156.0/22": "Selectel",
    "31.129.32.0/23": "Selectel",
    "31.129.34.0/23": "Selectel",
    "31.129.36.0/22": "Selectel",
    "31.129.40.0/24": "Selectel",
    "31.129.41.0/24": "Selectel",
    "31.129.42.0/23": "Selectel",
    "31.129.44.0/23": "Selectel",
    "31.129.46.0/23": "Selectel",
    "31.129.48.0/23": "Selectel",
    "31.129.50.0/23": "Selectel",
    "31.129.52.0/22": "Selectel",
    "31.129.56.0/23": "Selectel",
    "31.129.58.0/23": "Selectel",
    "79.141.64.0/20": "Selectel",
    "92.255.62.0/23": "Selectel",
    "185.42.164.0/22": "Selectel",
    "185.175.44.0/22": "Selectel",
    "185.193.90.0/23": "Selectel",
}

WHITELIST_SUBNETS = list(CIDR_NAME_MAPPING.keys())
WHITELIST_NETWORKS = []
WHITELIST_NAMES = []
for subnet_str, name in CIDR_NAME_MAPPING.items():
    try:
        net = ipaddress.ip_network(subnet_str)
        WHITELIST_NETWORKS.append(net)
        WHITELIST_NAMES.append(name)
    except Exception as e:
        log(f"Ошибка в подсети {subnet_str}: {e}")

# Список URL для парсинга (обновлён)
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://gitverse.ru/api/repos/Vsevj/OBS/raw/branch/master/wwh",
    "https://storage.yandexcloud.net/cid-vpn/whitelist.txt",
    "https://raw.githubusercontent.com/koteey/Ms.Kerosin-VPN/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/main-sub.txt",
    "https://raw.githubusercontent.com/FalerChannel/FalerChannel/refs/heads/main/configs",
    "https://raw.githubusercontent.com/officialdakari/psychic-octo-tribble/refs/heads/main/subwl.txt",
    "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs/url_work.txt",
    "https://raw.githubusercontent.com/Ai123999/WhiteeListSub/refs/heads/main/whitelistkeys",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist",
    "https://raw.githubusercontent.com/gbwltg/gbwl/refs/heads/main/m3EsPqwmlc",
    "https://gitverse.ru/api/repos/LowiK/LowiKLive/raw/branch/main/ObhodBSfree.txt",
    "https://raw.githubusercontent.com/bywarm/wlr/refs/heads/main/test.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt",
    "https://airlinkvpn.github.io/1.txt",
    "https://raw.githubusercontent.com/prominbro/KfWL/refs/heads/main/KfWL.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/BLACK_VLESS_RUS.txt",
    "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt",
]

# Словарь маркеров благодарности
THANKS_MARKERS = {
    '@YoutubeUnBlockRu': '@YoutubeUnBlockRu',
    'gbwl': '@gbwl',
    '9A%D0%9F%5D': '@rkp_channel',
}

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)

DEFAULT_MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "10"))

def _build_session(max_pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max_pool_size,
        pool_maxsize=max_pool_size,
        max_retries=Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
        ),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": CHROME_UA})
    return session

REQUESTS_SESSION = _build_session(max_pool_size=min(DEFAULT_MAX_WORKERS, len(URLS)))

def fetch_url(url: str, timeout: int = 15, max_attempts: int = 3) -> str:
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True
            if attempt == 2:
                verify = False
            elif attempt == 3:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme == "https":
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False
            response = REQUESTS_SESSION.get(modified_url, timeout=timeout, verify=verify)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as exc:
            if attempt < max_attempts:
                continue
            error_msg = str(exc)[:100]
            log("Ошибка загрузки " + url + ": " + error_msg)
            return ""
    return ""

def extract_host_port(config: str) -> tuple[str, int] | None:
    if not config:
        return None
    try:
        if config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    host = j.get('add') or j.get('host') or j.get('ip')
                    port = j.get('port')
                    if host and port:
                        return str(host), int(port)
            except Exception:
                pass
        patterns = [
            r'@([\w\.-]+):(\d{1,5})',
            r'host=([\w\.-]+).*?port=(\d{1,5})',
            r'address=([\w\.-]+).*?port=(\d{1,5})',
            r'//([\w\.-]+):(\d{1,5})',
        ]
        for pattern in patterns:
            match = re.search(pattern, config, re.IGNORECASE)
            if match:
                return match.group(1), int(match.group(2))
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})', config)
        if match:
            return match.group(1), int(match.group(2))
        match = re.search(r'([\w\.-]+):(\d{1,5})', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            if len(host) > 1 and ('.' in host or host.replace('.', '').replace('-', '').isalnum()):
                return host, port
    except Exception:
        pass
    return None

def generate_config_key(config: str) -> str:
    if not config:
        return ""
    try:
        if config.startswith("vless://"):
            parsed = urllib.parse.urlparse(config)
            username = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443
            query_params = urllib.parse.parse_qs(parsed.query)
            key_parts = [
                username,
                host,
                str(port),
                query_params.get('security', [''])[0],
                query_params.get('sni', [''])[0],
                query_params.get('sid', [''])[0],
                query_params.get('pbk', [''])[0],
                query_params.get('type', [''])[0],
                query_params.get('flow', [''])[0],
                query_params.get('fp', [''])[0],
                query_params.get('encryption', [''])[0],
            ]
            return "|".join([p for p in key_parts if p])
        elif config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    key_parts = [
                        j.get('id', ''),
                        j.get('add', ''),
                        str(j.get('port', '')),
                        j.get('net', ''),
                        j.get('host', ''),
                        j.get('path', ''),
                        j.get('tls', ''),
                        j.get('sni', ''),
                        j.get('type', ''),
                        j.get('ps', ''),
                    ]
                    return "|".join([p for p in key_parts if p])
            except Exception:
                pass
        elif config.startswith("trojan://"):
            parsed = urllib.parse.urlparse(config)
            username = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443
            query_params = urllib.parse.parse_qs(parsed.query)
            key_parts = [
                username,
                host,
                str(port),
                query_params.get('security', [''])[0],
                query_params.get('sni', [''])[0],
                query_params.get('type', [''])[0],
                query_params.get('flow', [''])[0],
                query_params.get('fp', [''])[0],
            ]
            return "|".join([p for p in key_parts if p])
        else:
            return config[:200]
    except Exception:
        return config[:100]

def is_ip_in_subnets(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return False
        for network in WHITELIST_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False

def get_cidr_name(ip_str: str) -> str | None:
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.version != 4:
            return None
        for network, name in zip(WHITELIST_NETWORKS, WHITELIST_NAMES):
            if ip in network:
                return name
        return None
    except ValueError:
        return None

def extract_sni(config: str) -> str:
    if not config:
        return ""
    try:
        if config.startswith(("vless://", "trojan://")):
            parsed = urllib.parse.urlparse(config)
            query_params = urllib.parse.parse_qs(parsed.query)
            sni_list = query_params.get('sni', [])
            if sni_list:
                return sni_list[0]
        elif config.startswith("vmess://"):
            payload = config[8:]
            rem = len(payload) % 4
            if rem:
                payload += '=' * (4 - rem)
            decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
            if decoded.startswith('{'):
                j = json.loads(decoded)
                sni = j.get('sni') or j.get('host') or j.get('add')
                if sni:
                    return sni
        host_port = extract_host_port(config)
        if host_port:
            host = host_port[0]
            try:
                ipaddress.ip_address(host)
                return ""
            except ValueError:
                return host
    except Exception:
        pass
    return ""

def download_and_process_url(url: str) -> list[str]:
    try:
        data = fetch_url(url)
        if not data:
            return []
        data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
        lines = data.splitlines()
        configs = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and len(line) > 10:
                if any(line.startswith(p) for p in ['vmess://', 'vless://', 'trojan://', 
                                                     'ss://', 'ssr://', 'tuic://', 
                                                     'hysteria://', 'hysteria2://']):
                    configs.append(line)
                elif '@' in line and ':' in line and line.count(':') >= 2:
                    configs.append(line)
        repo_name = url.split('/')[3] if '/' in url else 'unknown'
        log("✅ " + repo_name + ": " + str(len(configs)) + " конфигов")
        return configs
    except Exception as e:
        error_msg = str(e)[:100]
        log("Ошибка обработки " + url + ": " + error_msg)
        return []

def add_numbering_to_name(config: str, number: int, thanks_text: str = "", sni: str = "", cidr_text: str = "") -> str:
    try:
        proto = "CONFIG"
        if config.startswith("vmess://"):
            proto = "VMESS"
        elif config.startswith("vless://"):
            proto = "VLESS"
        elif config.startswith("trojan://"):
            proto = "TROJAN"
        elif config.startswith("ss://"):
            proto = "SS"
        elif config.startswith("ssr://"):
            proto = "SSR"
        elif config.startswith("tuic://"):
            proto = "TUIC"
        elif config.startswith("hysteria://"):
            proto = "HYSTERIA"
        elif config.startswith("hysteria2://"):
            proto = "HYSTERIA2"

        flag = ""
        if '#' in config:
            fragment = config.split('#', 1)[1]
            fragment_unquoted = urllib.parse.unquote(fragment)
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', fragment_unquoted)
        else:
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', config)
        if flag_match:
            flag = flag_match.group(0) + " "

        base_parts = [f"{number}. {flag}{proto}"]
        if sni:
            base_parts.append(f"SNI: {sni}")
        if cidr_text:
            base_parts.append(cidr_text)
        base_parts.append("TG: @wlrustg")
        if thanks_text:
            base_parts.append(f"Thanks: {thanks_text}")
        new_name = " | ".join(base_parts)

        if config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    j['ps'] = new_name
                    new_json = json.dumps(j, separators=(',', ':'))
                    encoded = base64.b64encode(new_json.encode()).decode()
                    return f"vmess://{encoded}"
            except Exception:
                pass
            return config
        elif config.startswith(("vless://", "trojan://", "ss://", "ssr://", "tuic://", "hysteria://", "hysteria2://")):
            base_part = config.rsplit('#', 1)[0] if '#' in config else config
            new_fragment = urllib.parse.quote(new_name, safe='')
            return f"{base_part}#{new_fragment}"
        else:
            base_part = config.rsplit('#', 1)[0] if '#' in config else config
            new_fragment = urllib.parse.quote(new_name, safe='')
            return f"{base_part}#{new_fragment}"
    except Exception as e:
        log(f"Ошибка добавления нумерации: {str(e)[:100]}")
        return config

def extract_existing_info(config: str) -> tuple:
    config_clean = config.strip()
    number_match = re.search(r'(?:#?\s*)(\d{1,3})(?:\.|\s+|$)', config_clean)
    number = number_match.group(1) if number_match else None
    flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', config_clean)
    flag = flag_match.group(0) if flag_match else ""
    tg_match = re.search(r'TG\s*:\s*@wlrustg', config_clean, re.IGNORECASE)
    tg = tg_match.group(0) if tg_match else ""
    return number, flag, tg

def process_configs_with_numbering(configs: list[str]) -> list[str]:
    processed_configs = []
    for i, config in enumerate(configs, 1):
        existing_number, _, _ = extract_existing_info(config)
        thanks_text = ""
        for marker, thanks in THANKS_MARKERS.items():
            if marker in config:
                thanks_text = thanks
                break
        sni = extract_sni(config)
        cidr_text = ""
        host_port = extract_host_port(config)
        if host_port:
            host = host_port[0]
            try:
                ipaddress.ip_address(host)
                if is_ip_in_subnets(host):
                    name = get_cidr_name(host)
                    if name:
                        cidr_text = f"CIDR: {name}"
                    else:
                        cidr_text = "CIDR"
            except ValueError:
                pass
        if existing_number and "TG: @wlrustg" in config:
            processed_configs.append(config)
        else:
            processed_configs.append(add_numbering_to_name(config, i, thanks_text, sni, cidr_text))
    return processed_configs

def prioritize_configs(configs: list[str]) -> list[str]:
    return sorted(configs, key=lambda c: '@YoutubeUnBlockRu' not in c)

def merge_and_deduplicate(all_configs: list[str]) -> tuple[list[str], list[str]]:
    if not all_configs:
        return [], []
    seen_full = set()
    seen_config_keys = set()
    unique_configs = []
    whitelist_configs = []
    duplicate_count = 0
    for config in all_configs:
        config = config.strip()
        if not config or config in seen_full:
            duplicate_count += 1
            continue
        seen_full.add(config)
        config_key = generate_config_key(config)
        if config_key and config_key in seen_config_keys:
            duplicate_count += 1
            continue
        seen_config_keys.add(config_key)
        unique_configs.append(config)
        host_port = extract_host_port(config)
        if host_port:
            host = host_port[0]
            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 4 and is_ip_in_subnets(str(ip)):
                    whitelist_configs.append(config)
            except ValueError:
                pass
    if duplicate_count > 0:
        log(f"🔍 Удалено {duplicate_count} дубликатов")
    return unique_configs, whitelist_configs

def save_to_file(configs: list[str], file_type: str, description: str = "", add_numbering: bool = False):
    if file_type == "merged":
        filepath = PATHS["merged"]
        filename = os.path.basename(filepath)
    elif file_type == "wl":
        filepath = PATHS["wl"]
        filename = os.path.basename(filepath)
    else:
        filepath = file_type
        filename = os.path.basename(filepath)
    try:
        os.makedirs(PATHS["base_dir"], exist_ok=True)
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            if 'Whitelist' in description:
                f.write("#profile-title: WL RUS (wl.txt)\n")
            elif 'Черный' in description or 'Black' in description:
                f.write("#profile-title: WL RUS (black.txt)\n")
            else:
                f.write("#profile-title: WL RUS (all)\n")
            f.write("#profile-update-interval: 24\n")
            f.write("#announce: Сервера из подписки должны использоваться ТОЛЬКО при белых списках!\n")
            f.write(f"# Обновлено: {offset}\n")
            f.write(f"# Всего конфигов: {len(configs)}\n")
            f.write("#" * 50 + "\n\n")
            processed = process_configs_with_numbering(configs) if add_numbering else configs
            for cfg in processed:
                f.write(cfg + "\n")
        log(f"💾 Сохранено {len(configs)} конфигов в {filename}")
    except Exception as e:
        log(f"Ошибка сохранения {filename}: {str(e)}")

def upload_to_github(filename: str, remote_path: str = None, branch: str = "main"):
    """
    Загружает файл на GitHub через прямой REST API, используя base64.
    """
    if not GITHUB_TOKEN:
        log("❌ GITHUB_TOKEN не задан, пропускаю загрузку на GitHub")
        return

    if not os.path.exists(filename):
        log(f"❌ Файл {filename} не найден для загрузки")
        return

    # Определяем путь в репозитории
    if remote_path is None:
        remote_path = os.path.basename(filename)

    # Читаем файл как бинарные данные
    with open(filename, "rb") as f:
        content_bytes = f.read()

    # Кодируем в base64 (стандарт GitHub API)
    content_b64 = base64.b64encode(content_bytes).decode('ascii')

    # Формируем URL для API
    repo_full_name = REPO.full_name if REPO else REPO_NAME
    url = f"https://api.github.com/repos/{repo_full_name}/contents/{remote_path}"
    headers = {
        "Authorization": f"token {GITHUB_TOKEN}",
        "Accept": "application/vnd.github.v3+json"
    }
    params = {"ref": branch}

    # Проверяем, существует ли уже файл, чтобы получить SHA
    sha = None
    try:
        get_resp = requests.get(url, headers=headers, params=params, timeout=15)
        if get_resp.status_code == 200:
            sha = get_resp.json().get("sha")
            log(f"📄 Файл {remote_path} существует, SHA: {sha[:8]}...")
        elif get_resp.status_code != 404:
            log(f"⚠️ Неожиданный ответ при проверке файла {remote_path}: {get_resp.status_code}")
            log(get_resp.text[:200])
    except Exception as e:
        log(f"⚠️ Ошибка при проверке файла: {str(e)[:100]}")

    # Подготавливаем данные для PUT
    data = {
        "message": f"🤖 Авто-обновление: {offset}",
        "content": content_b64,
        "branch": branch
    }
    if sha:
        data["sha"] = sha

    # Отправляем запрос на создание/обновление
    try:
        put_resp = requests.put(url, headers=headers, json=data, timeout=30)
        if put_resp.status_code in [200, 201]:
            log(f"✅ Файл {remote_path} успешно загружен на GitHub")
        else:
            log(f"❌ Ошибка {put_resp.status_code} при загрузке {remote_path}:")
            # Пытаемся получить детали ошибки
            try:
                error_json = put_resp.json()
                log(json.dumps(error_json, indent=2)[:500])
            except:
                log(put_resp.text[:500])
    except Exception as e:
        log(f"❌ Исключение при PUT-запросе: {str(e)[:200]}")

def update_readme(total_configs: int, wl_configs_count: int):
    if not REPO:
        log("Пропускаю обновление README (нет подключения)")
        return
    try:
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException:
            old_content = "# Объединенные конфиги VPN\n\n"
        raw_url_merged = f"https://github.com/{REPO_NAME}/raw/main/merged.txt"
        raw_url_wl = f"https://github.com/{REPO_NAME}/raw/main/githubmirror/wl.txt"
        raw_url_selected = f"https://github.com/{REPO_NAME}/raw/main/githubmirror/selected.txt"
        raw_url_black = f"https://github.com/{REPO_NAME}/raw/main/githubmirror/black.txt"
        time_parts = offset.split(" | ")
        time_part = time_parts[0] if len(time_parts) > 0 else ""
        date_part = time_parts[1] if len(time_parts) > 1 else ""
        new_section = f"""
## 📊 Статус обновления

| Файл | Описание | Конфигов | Время обновления | Дата |
|------|----------|----------|------------------|------|
| [`merged.txt`]({raw_url_merged}) | Все конфиги из {len(URLS)} источников | {total_configs} | {time_part} | {date_part} |
| [`wl.txt`]({raw_url_wl}) | Только конфиги из {len(WHITELIST_SUBNETS)} подсетей | {wl_configs_count} | {time_part} | {date_part} |
| [`selected.txt`]({raw_url_selected}) | Отборные админами конфиги | не знаю | {time_part} | {date_part} |
| [`black.txt`]({raw_url_black}) | Конфиги не в whitelist | {total_configs - wl_configs_count} | {time_part} | {date_part} |

"""
        sha = readme_file.sha if 'readme_file' in locals() else None
        REPO.update_file(path="README.md", message=f"📝 Обновление README: {total_configs} конфигов, {wl_configs_count} в whitelist",
                         content=new_section, sha=sha)
        log("📝 README.md обновлён")
    except Exception as e:
        log("Ошибка обновления README: " + str(e))

def process_selected_file():
    selected_file = PATHS["selected"]
    if not os.path.exists(selected_file):
        log("ℹ️ Файл selected.txt не найден")
        return []
    try:
        with open(selected_file, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        log(f"❌ Ошибка чтения selected.txt: {str(e)}")
        return []
    configs = []
    manual_comments = []
    skip_auto_header = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#profile-title: WL RUS (selected)"):
            skip_auto_header = True
            continue
        if skip_auto_header:
            if stripped.startswith("#") or not stripped:
                continue
            else:
                skip_auto_header = False
        if not stripped:
            if manual_comments and manual_comments[-1] != "":
                manual_comments.append("")
        elif stripped.startswith('#'):
            manual_comments.append(stripped)
        else:
            if any(stripped.startswith(p) for p in ['vmess://', 'vless://', 'trojan://', 
                                                     'ss://', 'ssr://', 'tuic://', 
                                                     'hysteria://', 'hysteria2://']):
                configs.append((len(configs), stripped))
            elif '@' in stripped and ':' in stripped and stripped.count(':') >= 2:
                configs.append((len(configs), stripped))
    if not configs:
        log("ℹ️ В selected.txt нет конфигов")
        return []
    try:
        config_indices = [idx for idx, _ in configs]
        raw_configs = [cfg for _, cfg in configs]
        seen_full = set()
        seen_config_keys = set()
        unique_configs_with_index = []
        duplicates_count = 0
        for idx, cfg in zip(config_indices, raw_configs):
            if cfg in seen_full:
                duplicates_count += 1
                continue
            seen_full.add(cfg)
            config_key = generate_config_key(cfg)
            if config_key and config_key in seen_config_keys:
                duplicates_count += 1
                continue
            seen_config_keys.add(config_key)
            unique_configs_with_index.append((idx, cfg))
        if duplicates_count > 0:
            log(f"🔍 Найдено {duplicates_count} дубликатов в selected.txt")
        unique_configs = [cfg for _, cfg in unique_configs_with_index]
        processed_configs = process_configs_with_numbering(unique_configs)
        processed_by_index = {}
        for (idx, _), processed in zip(unique_configs_with_index, processed_configs):
            processed_by_index[idx] = processed
        with open(selected_file, "w", encoding="utf-8") as f:
            f.write("#profile-title: WL RUS (selected)\n")
            f.write("#profile-update-interval: 24\n")
            f.write("#announce: Сервера из подписки должны использоваться ТОЛЬКО при белых списках!\n")
            if manual_comments:
                f.write("\n")
                for comment in manual_comments:
                    f.write(comment + ("\n" if comment == "" else "\n"))
            if processed_configs:
                if manual_comments:
                    f.write("\n")
                for i in range(len(processed_configs)):
                    if i in processed_by_index:
                        f.write(processed_by_index[i] + "\n")
                        if i < len(processed_configs) - 1:
                            f.write("\n")
        log(f"✅ Обработан selected.txt: {len(processed_configs)} конфигов")
        return processed_configs
    except Exception as e:
        log(f"❌ Ошибка обработки selected.txt: {str(e)}")
        return []

def filter_excluded_configs(configs, exclude_patterns=None, settings=None, excluded_file=None):
    if exclude_patterns is None:
        exclude_patterns = EXCLUDE_PATTERNS
    if settings is None:
        settings = EXCLUDE_SETTINGS.copy()
    else:
        settings = settings.copy()
    if excluded_file:
        settings["excluded_file"] = excluded_file
    filtered = []
    excluded = []
    stats = {}
    if not settings.get("case_sensitive", False):
        exclude_patterns = [p.lower() for p in exclude_patterns]
    for cfg in configs:
        cfg_check = cfg if settings.get("case_sensitive", False) else cfg.lower()
        excluded_flag = False
        reason = ""
        for pattern in exclude_patterns:
            if pattern.startswith("#"):
                if f"#{pattern[1:]}" in cfg_check:
                    excluded_flag = True
                    reason = f"remark содержит: {pattern}"
                    break
            elif pattern.startswith("@"):
                if f"@{pattern[1:]}" in cfg_check:
                    excluded_flag = True
                    reason = f"адрес содержит: {pattern}"
                    break
            elif pattern.startswith("/"):
                if f"path={pattern}" in cfg_check or f"path%3D{pattern}" in cfg_check:
                    excluded_flag = True
                    reason = f"path содержит: {pattern}"
                    break
            else:
                if pattern in cfg_check:
                    excluded_flag = True
                    reason = f"содержит: {pattern}"
                    break
        if excluded_flag:
            excluded.append(cfg)
            stats[reason] = stats.get(reason, 0) + 1
        else:
            filtered.append(cfg)
    if settings.get("log_excluded", True):
        log(f"🚫 Исключено: {len(excluded)}")
        if stats:
            for r, c in stats.items():
                log(f"   • {r}: {c}")
    if settings.get("save_excluded", True) and excluded:
        with open(settings.get("excluded_file", "excluded.txt"), "w", encoding="utf-8") as f:
            f.write("\n".join(excluded))
        log(f"💾 Исключённые сохранены в {settings['excluded_file']}")
    return filtered, excluded

def upload_to_cloud_ru(file_path: str, s3_path: str = None):
    if not all([CLOUD_RU_ENDPOINT, CLOUD_RU_ACCESS_KEY, CLOUD_RU_SECRET_KEY, CLOUD_RU_BUCKET]):
        log("❌ Пропускаю Cloud.ru: нет переменных")
        return
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        log("❌ boto3 не установлен")
        return
    if not os.path.exists(file_path):
        log(f"❌ Файл {file_path} не найден")
        return
    s3_path = s3_path or os.path.basename(file_path)
    try:
        s3 = boto3.client('s3',
                          endpoint_url=CLOUD_RU_ENDPOINT,
                          aws_access_key_id=CLOUD_RU_ACCESS_KEY,
                          aws_secret_access_key=CLOUD_RU_SECRET_KEY,
                          region_name=CLOUD_RU_REGION,
                          config=Config(signature_version='s3v4'))
        with open(file_path, 'rb') as f:
            s3.put_object(Bucket=CLOUD_RU_BUCKET, Key=s3_path, Body=f, ContentType='text/plain')
        log(f"✅ Загружено в Cloud.ru: {s3_path}")
    except Exception as e:
        log(f"❌ Ошибка Cloud.ru: {str(e)[:200]}")

def upload_to_gitverse(filename: str, remote_path: str = None):
    if not GITVERSE_TOKEN:
        log("❌ Пропускаю GitVerse: нет токена")
        return
    if not os.path.exists(filename):
        log(f"❌ Файл {filename} не найден")
        return
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        remote_path = remote_path or os.path.basename(filename)
        base_url = "https://api.gitverse.ru"
        headers = {
            "Authorization": f"Bearer {GITVERSE_TOKEN}",
            "Accept": "application/vnd.gitverse.object+json;version=1",
            "Content-Type": "application/json"
        }
        # Проверка аутентификации
        user_resp = requests.get(f"{base_url}/user", headers=headers, timeout=10)
        if user_resp.status_code != 200:
            log(f"❌ GitVerse auth failed: {user_resp.status_code}")
            return
        content_b64 = base64.b64encode(content.encode()).decode()
        # Проверяем существование файла
        sha = None
        url = f"{base_url}/repos/{GITVERSE_REPO_OWNER}/{GITVERSE_REPO_NAME}/contents/{remote_path}"
        params = {'ref': GITVERSE_BRANCH} if GITVERSE_BRANCH else {}
        get_resp = requests.get(url, headers=headers, params=params, timeout=10)
        if get_resp.status_code == 200:
            sha = get_resp.json().get('sha', '')
        data = {
            "message": f"🤖 Авто-обновление: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": content_b64,
        }
        if GITVERSE_BRANCH:
            data["branch"] = GITVERSE_BRANCH
        if sha:
            data["sha"] = sha
        put_resp = requests.put(url, headers=headers, json=data, timeout=15)
        if put_resp.status_code in [200, 201]:
            log(f"✅ GitVerse: {remote_path} обновлён")
        else:
            log(f"❌ GitVerse error {put_resp.status_code}: {put_resp.text[:200]}")
    except Exception as e:
        log(f"❌ GitVerse error: {str(e)}")

def main():
    log("📥 Загрузка конфигов...")
    all_configs = []
    max_workers = min(DEFAULT_MAX_WORKERS, len(URLS))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_and_process_url, url): url for url in URLS}
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                configs = future.result(timeout=30)
                if configs:
                    all_configs.extend(configs)
            except Exception as e:
                log(f"Таймаут/ошибка {url}: {str(e)[:50]}")
    log(f"📊 Скачано всего: {len(all_configs)} конфигов")
    log("🔧 Обработка selected.txt...")
    selected_configs = process_selected_file()
    if not all_configs:
        log("❌ Нет конфигов, выход")
        return
    all_configs.extend(selected_configs)
    log("⭐ Приоритизация @YoutubeUnBlockRu...")
    all_configs = prioritize_configs(all_configs)
    log("🔄 Дедупликация...")
    unique_configs, whitelist_configs = merge_and_deduplicate(all_configs)
    log(f"🔄 После дедупликации: {len(unique_configs)} конфигов")
    log(f"🛡️ Whitelist: {len(whitelist_configs)}")
    log("🚫 Применение исключений...")
    filtered_unique, excluded_unique = filter_excluded_configs(unique_configs, excluded_file="excluded_merged.txt")
    filtered_wl, excluded_wl = filter_excluded_configs(whitelist_configs, excluded_file="excluded_wl.txt")
    unique_configs, whitelist_configs = filtered_unique, filtered_wl
    log(f"✅ После исключений: merged={len(unique_configs)}, wl={len(whitelist_configs)}")

    # NEW: compute black configs (all unique minus whitelist)
    whitelist_set = set(whitelist_configs)
    black_configs = [cfg for cfg in unique_configs if cfg not in whitelist_set]
    log(f"⚫ Черный список (не в whitelist): {len(black_configs)} конфигов")

    os.makedirs("confs", exist_ok=True)
    save_to_file(unique_configs, "merged", "Объединённые конфиги", add_numbering=True)
    save_to_file(whitelist_configs, "wl", "Whitelist конфиги", add_numbering=True)
    save_to_file(black_configs, PATHS["black"], "Черный список (не в whitelist)", add_numbering=True)

    log("🌐 Загрузка на GitHub...")
    upload_to_github(PATHS["merged"])
    upload_to_github(PATHS["wl"])
    upload_to_github(PATHS["selected"])
    upload_to_github(PATHS["black"])

    log("☁️ Загрузка в Cloud.ru...")
    for s3_name, local in {
        "merged.txt": PATHS["merged"],
        "wl.txt": PATHS["wl"],
        "selected.txt": PATHS["selected"],
        "black.txt": PATHS["black"],
    }.items():
        if os.path.exists(local):
            upload_to_cloud_ru(local, s3_name)

    if GITVERSE_TOKEN:
        log("🚀 Загрузка на GitVerse...")
        for remote, local in {
            "merged.txt": PATHS["merged"],
            "wl.txt": PATHS["wl"],
            "selected.txt": PATHS["selected"],
            "black.txt": PATHS["black"],
        }.items():
            if os.path.exists(local):
                upload_to_gitverse(local, remote)

    update_readme(len(unique_configs), len(whitelist_configs))

    log("="*60)
    log("📊 ИТОГИ:")
    log(f"   🌐 Источников: {len(URLS)}")
    log(f"   📥 Из URL: {len(all_configs)-len(selected_configs)}")
    log(f"   🔧 Из selected.txt: {len(selected_configs)}")
    log(f"   🔄 Уникальных: {len(filtered_unique)}")
    log(f"   🚫 Исключено: {len(excluded_unique)+len(excluded_wl)}")
    log(f"   🛡️ Whitelist: {len(filtered_wl)}")
    log(f"   ⚫ Blacklist: {len(black_configs)}")
    log("="*60)

    print("\n📋 ЛОГИ ВЫПОЛНЕНИЯ (" + offset + "):")
    print("="*60)
    for line in LOGS_BY_FILE[0]:
        print(line)

if __name__ == "__main__":
    main()
