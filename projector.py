# -*- coding: utf-8 -*-
"""
极米 H3S 投影仪局域网控制器

原理：
  极米投影仪开机后会暴露一个标准 DLNA (UPnP) 渲染器，控制入口在 1035 端口。
  本程序作为 DLNA 控制端 (Controller)，通过 SOAP 调用三个服务：
    AVTransport        -> 推流、播放、暂停、停止、跳进度
    RenderingControl   -> 音量、静音
    ConnectionManager  -> 查询支持的媒体格式
  DLNA 是"拉模式"：投影仪会主动回到本机下载媒体文件，所以投屏时本程序
  会临时启动一个带 Range 支持的 HTTP 服务作为媒体源。

使用：
  图形界面： python projector.py --gui      （或双击 start_gui.bat）
  命令行：   python projector.py status
             python projector.py cast 视频.mp4
             python projector.py pause | stop | resume | vol 40 | seek 120

注意：
  系统代理（Clash 等）会劫持发往 192.168.x.x 的 HTTP 请求并返回 502，
  因此本程序所有请求都显式绕过代理（见 OPENER）。
"""

import argparse
import hashlib
import json
import mimetypes
import os
import re
import socket
import sys
import threading
import time
import traceback
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urljoin, urlsplit

# ---------------------------------------------------------------- 全局配置

HERE = os.path.dirname(os.path.abspath(__file__))
VENDOR_DIR = os.path.join(HERE, "vendor")
if os.path.isdir(VENDOR_DIR) and VENDOR_DIR not in sys.path:
    sys.path.insert(0, VENDOR_DIR)          # 自带依赖（Pillow），不污染全局环境

CONFIG_PATH = os.path.join(HERE, "device.json")
ERROR_LOG = os.path.join(HERE, "error.log")
DLNA_PORT = 1035                       # 极米 DLNA 描述端口
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # 关键：绕过系统代理


def _init_streams():
    """pythonw.exe 没有控制台，sys.stdout / sys.stderr 是 None，
    任何 print 或异常回溯都会失效（进程直接消失且无痕迹）。
    这里把它们接到日志文件，并接管未捕获异常。"""
    if sys.stdout is None or sys.stderr is None:
        try:
            f = open(ERROR_LOG, "a", encoding="utf-8", buffering=1)
        except Exception:
            return
        if sys.stdout is None:
            sys.stdout = f
        if sys.stderr is None:
            sys.stderr = f

    def hook(exc_type, exc, tb):
        traceback.print_exception(exc_type, exc, tb, file=sys.stderr)

    def thook(args):
        traceback.print_exception(args.exc_type, args.exc_value, args.exc_traceback,
                                 file=sys.stderr)

    sys.excepthook = hook
    threading.excepthook = thook


_init_streams()

MIN_VIDEO_BYTES = 1024      # 小于 1KB 的文件视为空/损坏，直接过滤

VIDEO_EXT = (".mp4", ".mkv", ".avi", ".mov", ".ts", ".webm", ".flv", ".wmv",
             ".m4v", ".rmvb", ".mpg", ".mpeg", ".m2ts", ".mp3", ".flac", ".wav")

MIME_MAP = {
    ".mp4": "video/mp4", ".mkv": "video/x-matroska", ".avi": "video/x-msvideo",
    ".mov": "video/quicktime", ".ts": "video/mp2t", ".webm": "video/webm",
    ".flv": "video/x-flv", ".wmv": "video/x-ms-wmv", ".m4v": "video/mp4",
    ".mp3": "audio/mpeg", ".flac": "audio/flac", ".wav": "audio/wav",
    ".aac": "audio/aac", ".m4a": "audio/mp4", ".ogg": "audio/ogg",
    ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
    ".gif": "image/gif", ".bmp": "image/bmp",
}


def log(*args):
    print(time.strftime("[%H:%M:%S]"), *args, flush=True)


# ---------------------------------------------------------------- 网络工具

def local_ip_for(target_ip):
    """取本机在 target_ip 所在网段的那张网卡的 IP（避免选到 Clash 虚拟网卡）。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((target_ip, 9))
        return s.getsockname()[0]
    except Exception:
        return "0.0.0.0"
    finally:
        s.close()


def local_ips():
    """枚举本机所有可用的 IPv4 地址，过滤掉回环、VPN 虚拟网段。"""
    ips = set()
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ips.add(info[4][0])
    except Exception:
        pass
    for probe in ("223.5.5.5", "192.168.1.1"):
        ip = local_ip_for(probe)
        if ip != "0.0.0.0":
            ips.add(ip)
    return [ip for ip in ips
            if not ip.startswith("127.") and not ip.startswith("169.254.")
            and not re.match(r"^198\.(18|19)\.", ip)]


def tcp_open(ip, port, timeout=0.4):
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        s.close()


def probe_dlna(ip, port=DLNA_PORT, timeout=1.5):
    """判断 ip:port 上是否真的是一个 DLNA 渲染器。

    不能只靠 TCP 握手：Clash 之类的 TUN 代理会替不存在的 IP 直接返回
    SYN-ACK，导致整段扫描出现大量假阳性。真实设备会立刻回 HTTP 200 +
    description XML，假连接只会返回 0 字节就断开。
    """
    s = socket.socket()
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.sendall(b"GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % ip.encode())
        buf = b""
        while len(buf) < 65536:
            chunk = s.recv(8192)
            if not chunk:
                break
            buf += chunk
            if b"</root>" in buf:
                break
        return b"<root" in buf and b"MediaRenderer" in buf
    except Exception:
        return False
    finally:
        s.close()


def http_get(url, timeout=4):
    req = urllib.request.Request(url, headers={"User-Agent": "ProjectorCtl/1.0"})
    with OPENER.open(req, timeout=timeout) as r:
        return r.read(500000).decode("utf-8", "ignore")


# ---------------------------------------------------------------- 设备发现

def ssdp_scan(wait=3.5):
    """SSDP 组播搜索，返回 [{"ip", "port", "location"}]。

    LOCATION 里带的是设备真实的 HTTP 描述端口。极米的 DLNA 应用每次重启
    会换一个动态端口（实测见过 1035、1694），所以这个端口必须从广播里读，
    不能写死，否则应用一重启程序就"找不到设备"。
    """
    found = {}
    msg = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
           'MAN: "ssdp:discover"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n').encode()
    for lip in local_ips():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((lip, 0))
        except OSError:
            s.close()
            continue
        s.settimeout(1.0)
        for _ in range(3):
            try:
                s.sendto(msg, ("239.255.255.250", 1900))
            except OSError:
                break
            time.sleep(0.2)
        t0 = time.time()
        while time.time() - t0 < wait:
            try:
                data, addr = s.recvfrom(65535)
            except socket.timeout:
                continue
            loc = ""
            for line in data.decode("utf-8", "ignore").splitlines():
                if line.lower().startswith("location:"):
                    loc = line.split(":", 1)[1].strip()
                    break
            if not loc:
                continue
            try:
                port = urlsplit(loc).port or 80
            except ValueError:
                continue
            found[(addr[0], port)] = {"ip": addr[0], "port": port, "location": loc}
        s.close()
    return list(found.values())


def scan_dlna_ports(ip, lo=1024, hi=10000, timeout=0.6):
    """已知设备 IP 但端口未知时，扫这台机器的高位端口找 DLNA 描述页。"""
    import concurrent.futures
    ports = list(range(lo, hi + 1))

    def probe(p):
        return p if probe_dlna(ip, p, timeout) else None

    hits = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=200) as ex:
        for r in ex.map(probe, ports):
            if r:
                hits.append(r)
    return hits


def subnet_scan(port=DLNA_PORT, timeout=1.5):
    """兜底方案：扫本机所在 /24 网段，用 HTTP 描述页验证，避免假阳性。"""
    import concurrent.futures
    result = []
    for lip in local_ips():
        prefix = lip.rsplit(".", 1)[0]
        hosts = ["%s.%d" % (prefix, i) for i in range(1, 255)]
        with concurrent.futures.ThreadPoolExecutor(max_workers=128) as ex:
            for ip, ok in zip(hosts, ex.map(lambda h: probe_dlna(h, port, timeout), hosts)):
                if ok:
                    result.append(ip)
    return result


# ---------------------------------------------------------------- DLNA 控制端

def _localname(tag):
    return tag.rsplit("}", 1)[-1]


class Projector:
    """一个 DLNA MediaRenderer 设备的控制封装。"""

    def __init__(self, ip, port=DLNA_PORT, desc_url=None):
        self.ip = ip
        self.port = port
        # 描述地址以 SSDP 广播给的为准；只有拿不到时才按默认端口拼。
        self.desc_url = desc_url or ("http://%s:%d/" % (ip, port))
        self.name = ""
        self.model = ""
        self.manufacturer = ""
        self.manufacturer_url = ""
        self.services = {}   # {"AVTransport": (serviceType, controlURL), ...}
        self.last_error = ""

    # ---- 连接与描述 ----
    def connect(self):
        try:
            xml = http_get(self.desc_url, timeout=4)
        except Exception as e:
            self.last_error = "取设备描述失败: %s" % e
            return False
        try:
            root = ET.fromstring(xml)
        except ET.ParseError as e:
            self.last_error = "描述 XML 解析失败: %s" % e
            return False
        for el in root.iter():
            tag = _localname(el.tag)
            if tag == "friendlyName" and el.text:
                self.name = el.text.strip()
            elif tag == "modelName" and el.text:
                self.model = el.text.strip()
            elif tag == "manufacturer" and el.text:
                self.manufacturer = el.text.strip()
            elif tag == "manufacturerURL" and el.text:
                self.manufacturer_url = el.text.strip()
        for el in root.iter():
            if _localname(el.tag) != "service":
                continue
            stype = ctrl = None
            for child in el:
                if _localname(child.tag) == "serviceType":
                    stype = (child.text or "").strip()
                elif _localname(child.tag) == "controlURL":
                    ctrl = (child.text or "").strip()
            if stype and ctrl:
                short = stype.split(":")[-2]          # urn:schemas-upnp-org:service:AVTransport:1
                self.services[short] = (stype, urljoin(self.desc_url, ctrl))
        if not self.services:
            self.last_error = "设备未提供可用服务"
            return False
        return True

    # ---- SOAP 底层 ----
    def _soap(self, service, action, body="", timeout=6):
        if service not in self.services:
            raise RuntimeError("设备不支持 %s 服务" % service)
        stype, url = self.services[service]
        payload = (
            '<?xml version="1.0" encoding="utf-8"?>'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            '<u:%s xmlns:u="%s">%s</u:%s></s:Body></s:Envelope>'
            % (action, stype, body, action)
        )
        req = urllib.request.Request(
            url, data=payload.encode("utf-8"),
            headers={"Content-Type": 'text/xml; charset="utf-8"',
                     "SOAPAction": '"%s#%s"' % (stype, action)})
        with OPENER.open(req, timeout=timeout) as r:
            return ET.fromstring(r.read())

    @staticmethod
    def _val(root, name, default=""):
        for el in root.iter():
            if _localname(el.tag) == name:
                return (el.text or "").strip() or default
        return default

    # ---- 状态 ----
    def state(self):
        r = self._soap("AVTransport", "GetTransportInfo", "<InstanceID>0</InstanceID>")
        return self._val(r, "CurrentTransportState", "UNKNOWN")

    def position(self):
        """返回 (当前秒, 总秒)。"""
        r = self._soap("AVTransport", "GetPositionInfo", "<InstanceID>0</InstanceID>")
        return hms_to_sec(self._val(r, "RelTime", "00:00:00")), hms_to_sec(self._val(r, "TrackDuration", "00:00:00"))

    def current_uri(self):
        r = self._soap("AVTransport", "GetMediaInfo", "<InstanceID>0</InstanceID>")
        return self._val(r, "CurrentURI")

    # ---- 播放控制 ----
    def set_uri(self, url, mime, title=None):
        if mime.startswith("image/"):
            cls = "object.item.imageItem.photo"
        elif mime.startswith("audio/"):
            cls = "object.item.audioItem.musicTrack"
        else:
            cls = "object.item.videoItem.movie"
        title = title or os.path.basename(url.split("?")[0])
        meta = (
            '<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" '
            'xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">'
            '<item id="1" parentID="0" restricted="1"><dc:title>%s</dc:title>'
            '<upnp:class>%s</upnp:class>'
            '<res protocolInfo="http-get:*:%s:*">%s</res></item></DIDL-Lite>'
            % (esc(title), cls, mime, esc(url))
        )
        self._soap("AVTransport", "SetAVTransportURI",
                   "<InstanceID>0</InstanceID><CurrentURI>%s</CurrentURI>"
                   "<CurrentURIMetaData>%s</CurrentURIMetaData>" % (esc(url), esc(meta)))

    def play(self):
        self._soap("AVTransport", "Play", "<InstanceID>0</InstanceID><Speed>1</Speed>")

    def pause(self):
        self._soap("AVTransport", "Pause", "<InstanceID>0</InstanceID>")

    def stop(self):
        self._soap("AVTransport", "Stop", "<InstanceID>0</InstanceID>")

    def seek(self, seconds):
        self._soap("AVTransport", "Seek",
                   "<InstanceID>0</InstanceID><Unit>REL_TIME</Unit><Target>%s</Target>"
                   % sec_to_hms(seconds))

    # ---- 音量 ----
    def volume(self):
        r = self._soap("RenderingControl", "GetVolume",
                       "<InstanceID>0</InstanceID><Channel>Master</Channel>")
        return int(self._val(r, "CurrentVolume", "0") or 0)

    def set_volume(self, value):
        value = max(0, min(100, int(value)))
        self._soap("RenderingControl", "SetVolume",
                   "<InstanceID>0</InstanceID><Channel>Master</Channel>"
                   "<DesiredVolume>%d</DesiredVolume>" % value)
        return value


def esc(s):
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
             .replace('"', "&quot;"))


def hms_to_sec(t):
    if not t:
        return 0
    parts = t.split(":")
    try:
        parts = [float(p) for p in parts]
    except ValueError:
        return 0
    sec = 0.0
    for p in parts:
        sec = sec * 60 + p
    return int(sec)


def is_playable_file(path):
    """过滤空文件/损坏文件——0 字节的视频放进去必然播放失败。"""
    try:
        return os.path.getsize(path) >= MIN_VIDEO_BYTES
    except OSError:
        return False


PLAYLIST_PATH = os.path.join(HERE, "playlist.json")


def save_playlist(items, current):
    """把播放列表写到磁盘，下次启动自动恢复。"""
    try:
        with open(PLAYLIST_PATH, "w", encoding="utf-8") as f:
            json.dump({"items": list(items), "current": current}, f,
                      ensure_ascii=False, indent=2)
    except OSError:
        pass


def load_playlist():
    """读回播放列表；顺手丢掉已经不存在或是空文件的条目。"""
    try:
        with open(PLAYLIST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return [], None, 0
    raw = data.get("items") or []
    items = [p for p in raw if isinstance(p, str) and is_playable_file(p)]
    dropped = len(raw) - len(items)
    current = data.get("current")
    if current is not None and not (0 <= current < len(items)):
        current = None
    return items, current, dropped


def natural_key(text):
    """按数字大小排序，避免 第10集 排在 第2集 前面。"""
    parts = re.split(r"(\d+)", text)
    return [(0, int(p)) if p.isdigit() else (1, p.lower()) for p in parts if p != ""]


def sec_to_hms(sec):
    sec = max(0, int(sec))
    return "%02d:%02d:%02d" % (sec // 3600, (sec % 3600) // 60, sec % 60)


# ---------------------------------------------------------------- 本机媒体服务

class _MediaHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _serve(self, head_only=False):
        path = self.path.split("?")[0]
        state = self.server.state
        f = state.get("file")
        if not f or not os.path.isfile(f) or path not in ("/", "/" + state.get("name", "")):
            self.send_error(404)
            return
        size = os.path.getsize(f)
        start, end, code = 0, size - 1, 200
        rng = self.headers.get("Range")
        if rng:
            m = re.match(r"bytes=(\d*)-(\d*)", rng)
            if m:
                if m.group(1):
                    start = int(m.group(1))
                if m.group(2):
                    end = min(int(m.group(2)), size - 1)
                if start >= size:
                    self.send_error(416)
                    return
                code = 206
        self.send_response(code)
        self.send_header("Content-Type", state.get("mime", "application/octet-stream"))
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(end - start + 1))
        if code == 206:
            self.send_header("Content-Range", "bytes %d-%d/%d" % (start, end, size))
        self.end_headers()
        if head_only:
            return
        with open(f, "rb") as fp:
            fp.seek(start)
            remain = end - start + 1
            while remain > 0:
                chunk = fp.read(min(262144, remain))
                if not chunk:
                    break
                try:
                    self.wfile.write(chunk)
                    state["sent"] = state.get("sent", 0) + len(chunk)
                except (BrokenPipeError, ConnectionResetError):
                    return
                remain -= len(chunk)

    def do_GET(self):
        self._serve(False)

    def do_HEAD(self):
        self._serve(True)


class _MediaServer(ThreadingHTTPServer):
    """投影仪播放结束后会强制断开连接，默认实现会把这类正常断连
    当成异常打到 stderr/日志里，这里静默掉。"""
    daemon_threads = True
    allow_reuse_address = True

    def handle_error(self, request, client_address):
        import sys as _sys
        exc = _sys.exc_info()[1]
        if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
            return
        ThreadingHTTPServer.handle_error(self, request, client_address)


class MediaServer:
    """给投影仪提供媒体下载的临时 HTTP 服务。"""

    def __init__(self, host):
        self.host = host
        self.state = {"file": None, "mime": "application/octet-stream", "name": "",
                      "title": "", "sent": 0}
        self.httpd = None
        self.port = None

    def start(self):
        for port in range(8765, 8865):
            try:
                httpd = _MediaServer((self.host, port), _MediaHandler)
            except OSError:
                continue
            httpd.state = self.state
            self.httpd, self.port = httpd, port
            threading.Thread(target=httpd.serve_forever, daemon=True).start()
            return port
        raise RuntimeError("本机 8765-8864 端口全被占用，无法启动媒体服务")

    # 实测播放器接受真正的 mkv（video/x-matroska），不需要换壳；
    # 真正会翻车的是 URL 文件名里的空格、方括号、中文等字符。
    # 这里保留一个空表，将来遇到必须换扩展名的格式再往里加。
    DISGUISE_EXT = {}

    def url_for(self, path):
        ext = os.path.splitext(path)[1].lower()
        real = os.path.basename(path)
        out_ext = self.DISGUISE_EXT.get(ext, ext) or ext
        mime = MIME_MAP.get(ext) or mimetypes.guess_type(path)[0] or "application/octet-stream"
        if ext in self.DISGUISE_EXT:
            mime = "video/mp4"
        # 播放器处理不了带空格/方括号/中文的 URL（会直接放弃拉流），
        # 所以对外只暴露一个纯 ASCII 的短名字，真实文件名放在 DIDL title 里。
        safe = re.sub(r"[^A-Za-z0-9._-]", "", os.path.splitext(real)[0])[:32].strip("._-")
        if len(safe) < 3:
            safe = hashlib.md5(real.encode("utf-8")).hexdigest()[:10]
        name = safe + out_ext
        self.state["file"] = path
        self.state["mime"] = mime
        self.state["name"] = name
        self.state["title"] = real
        self.state["sent"] = 0
        return "http://%s:%d/%s" % (self.host, self.port, name), mime

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd = None


# ---------------------------------------------------------------- 设备连接流程

def verify_started(proj, server, seconds=3.0):
    """投屏后自检：设备接受了指令却没来拉流，通常是它的播放器没被唤醒。"""
    time.sleep(seconds)
    try:
        st = proj.state()
    except Exception:
        return True
    if st == "STOPPED" and server.state.get("sent", 0) == 0:
        return False
    return True


def load_config():
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def save_config(proj):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump({"ip": proj.ip, "port": proj.port, "name": proj.name},
                      f, ensure_ascii=False, indent=2)
    except Exception:
        pass


def is_system_renderer(proj):
    """判断是不是投影仪系统自带的投屏服务（而不是某个 App 临时注册的）。

    XGIMI 固件里的投屏组件基于 Platinum SDK，描述里 manufacturer 是
    jimi/xgimi、model 是 AV Renderer Device。这类渲染器随系统启动，
    不依赖任何第三方 App，应该优先选它。
    """
    blob = ("%s %s %s" % (proj.manufacturer, proj.manufacturer_url, proj.model)).lower()
    return any(k in blob for k in ("jimi", "xgimi"))


def try_connect(ip, port=DLNA_PORT, desc_url=None):
    if not probe_dlna(ip, port):
        return None
    p = Projector(ip, port, desc_url)
    return p if p.connect() else None


def missing_dlna_hint():
    """设备在线但 DLNA 服务没跑时说清楚原因。

    极米投影仪的 DLNA 渲染器是"云视听小电视"之类的应用注册的，
    投影仪重启或换 WiFi 后应用不在前台，1035 就会直接拒绝连接，
    但 7100/8080 这些系统端口仍然在。
    """
    cfg = load_config()
    ip = cfg.get("ip")
    if not ip:
        return ""
    for port in (7100, 8080):
        if tcp_open(ip, port, 0.6):
            return ("投影仪 %s 在线，但 DLNA 服务没启动。"
                    "请在投影仪上打开「云视听小电视」再点重连。" % ip)
    return ""


def find_projector(verbose=True, ip=None):
    """发现顺序：缓存地址 -> SSDP(真实端口) -> 单机端口扫描 -> 网段扫描。"""

    def usable(p):
        if p and "AVTransport" in p.services:
            save_config(p)
            return p
        return None

    cfg = load_config()

    if ip:
        p = try_connect(ip, cfg.get("port", DLNA_PORT))
        if usable(p):
            return p
        for d in ssdp_scan():
            if d["ip"] == ip:
                p = usable(try_connect(d["ip"], d["port"], d["location"]))
                if p:
                    return p
        return None

    # 1) 上次成功的地址，端口没变就是秒连
    if cfg.get("ip"):
        p = try_connect(cfg["ip"], cfg.get("port", DLNA_PORT))
        if usable(p):
            if verbose:
                log("已连接上次的设备:", p.name, "%s:%d" % (p.ip, p.port))
            return p

    # 2) SSDP：应用重启换了端口时靠这里纠正
    if verbose:
        log("SSDP 搜索中…")
    candidates = []
    for d in ssdp_scan():
        p = try_connect(d["ip"], d["port"], d["location"])
        if p and "AVTransport" in p.services:
            candidates.append(p)
    if candidates:
        # 同一台设备上可能同时存在系统投屏服务和某个 App 注册的渲染器，
        # 优先用系统自带的那个：它随固件启动，不依赖用户装了什么应用。
        candidates.sort(key=lambda x: is_system_renderer(x), reverse=True)
        if verbose:
            for c in candidates:
                log("  渲染器[%s]: %s  %s:%d  %s" % (
                    "系统" if is_system_renderer(c) else "应用",
                    c.name, c.ip, c.port, c.manufacturer or "?"))
            log("选用:", candidates[0].name, "%s:%d" % (candidates[0].ip, candidates[0].port))
        save_config(candidates[0])
        return candidates[0]

    # 3) 设备还在线但端口未知：只扫这一台机器
    if cfg.get("ip") and tcp_open(cfg["ip"], 7100, 0.6):
        if verbose:
            log("设备在线但端口未知，扫描端口…")
        for port in scan_dlna_ports(cfg["ip"]):
            p = usable(try_connect(cfg["ip"], port))
            if p:
                return p

    # 4) 兜底：扫整个网段的默认端口
    if verbose:
        log("按端口扫描网段中…")
    for ipc in subnet_scan():
        p = usable(try_connect(ipc))
        if p:
            return p
    return None


# ---------------------------------------------------------------- 命令行

def build_cli():
    ap = argparse.ArgumentParser(description="极米投影仪局域网控制器")
    ap.add_argument("--gui", action="store_true", help="打开图形界面")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--ip", help="指定投影仪 IP（跳过自动发现）")
    sub = ap.add_subparsers(dest="cmd")

    sub.add_parser("discover", help="扫描局域网里的投影仪")
    sub.add_parser("status", help="查看播放状态与音量", parents=[common])

    p_cast = sub.add_parser("cast", help="投屏一个文件", parents=[common])
    p_cast.add_argument("file")
    p_cast.add_argument("--volume", type=int)

    sub.add_parser("play", help="继续播放", parents=[common])
    sub.add_parser("pause", help="暂停", parents=[common])
    sub.add_parser("stop", help="停止", parents=[common])

    p_vol = sub.add_parser("vol", help="设置音量 0-100", parents=[common])
    p_vol.add_argument("value", type=int)

    p_seek = sub.add_parser("seek", help="跳转到第 N 秒", parents=[common])
    p_seek.add_argument("seconds", type=int)
    return ap


def cli(argv):
    args = build_cli().parse_args(argv)

    if args.cmd == "discover":
        found = ssdp_scan()
        if found:
            for d in found:
                log("SSDP: %s:%d  %s" % (d["ip"], d["port"], d["location"]))
        else:
            log("SSDP: 无响应")
        log("默认端口扫描:", subnet_scan() or "无")
        return 0

    if not args.cmd:
        build_cli().print_help()
        return 1

    proj = find_projector(ip=args.ip)
    if not proj:
        log("没有找到投影仪，请确认它已开机并和电脑在同一 WiFi")
        hint = missing_dlna_hint()
        if hint:
            log(hint)
        return 2
    log("设备:", proj.name or "(未知)", "|", proj.ip, "|", proj.model)

    if args.cmd == "status":
        cur, total = proj.position()
        log("状态: %s  进度: %s / %s  音量: %d" %
            (proj.state(), sec_to_hms(cur), sec_to_hms(total), proj.volume()))

    elif args.cmd == "pause":
        proj.pause()
        log("已暂停")

    elif args.cmd == "play":
        proj.play()
        log("继续播放")

    elif args.cmd == "stop":
        proj.stop()
        log("已停止")

    elif args.cmd == "vol":
        log("音量设为", proj.set_volume(args.value))

    elif args.cmd == "seek":
        proj.seek(args.seconds)
        log("已跳转到", sec_to_hms(args.seconds))

    elif args.cmd == "cast":
        path = os.path.abspath(args.file)
        if not os.path.isfile(path):
            log("文件不存在:", path)
            return 3
        host = local_ip_for(proj.ip)
        server = MediaServer(host)
        port = server.start()
        url, mime = server.url_for(path)
        log("媒体服务 %s:%d  类型 %s" % (host, port, mime))
        if args.volume is not None:
            proj.set_volume(args.volume)
        proj.set_uri(url, mime, title=os.path.basename(path))
        proj.play()
        log("已推送:", os.path.basename(path), "| 对外地址:", url.rsplit("/", 1)[-1])
        if not verify_started(proj, server):
            log("投影仪接受了指令但没有来拉流——请在投影仪上按一下遥控器唤醒屏幕后重试")
        log("按住 Ctrl+C 结束投屏")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            try:
                proj.stop()
            except Exception:
                pass
            server.stop()
            log("已停止")
    return 0


# ---------------------------------------------------------------- 图形界面

def run_gui():
    import queue
    import tkinter as tk
    from tkinter import filedialog, font as tkfont, messagebox

    try:
        from PIL import Image, ImageDraw, ImageFont, ImageTk
    except ImportError:
        messagebox.showerror("缺少依赖", "找不到 Pillow。请确认程序目录下的 vendor 文件夹完整。")
        return

    BG = "#FFFFFF"
    PANEL = "#F7F8FA"
    BORDER = "#E6E8EC"
    TRACK = "#E5E9F0"
    TEXT = "#1B1F24"
    SUB = "#5B6470"
    TER = "#8A919B"
    ACCENT = "#2563EB"
    ACCENT_D = "#1D4ED8"
    ACCENT_SOFT = "#E8F0FE"
    OK = "#1D9E75"
    ERR = "#E24B4A"
    BTN = "#F2F4F8"
    BTN_A = "#E6EAF1"
    FONT = "Microsoft YaHei UI"
    FONT_FILE = r"C:\Windows\Fonts\msyh.ttc"
    SS = 4

    root = tk.Tk()
    root.title("投影仪控制台")
    root.geometry("960x620")
    root.minsize(900, 560)
    root.configure(bg=BG)
    try:
        root.iconbitmap(os.path.join(HERE, "jimi.ico"))
    except Exception:
        pass

    app = {"proj": None, "server": None, "closing": False, "polling": False,
           "state": "STOPPED", "total": 0, "cur": 0, "max_pos": 0,
           "playlist": [], "current_index": None, "muted": False, "prev_vol": 35,
           "logwin": None, "last_sent": 0, "loglines": [], "title": "未选择媒体"}

    ui_q = queue.Queue()

    def post(fn):
        ui_q.put(fn)

    def drain():
        try:
            while True:
                ui_q.get_nowait()()
        except queue.Empty:
            pass
        except Exception:
            pass
        if not app["closing"]:
            root.after(60, drain)

    # ---------------- 抗锯齿素材 ----------------
    class Assets:
        """所有圆形/圆角元素用 4 倍超采样绘制再缩小，消除 GDI 锯齿。"""

        def __init__(self):
            self.cache = {}
            self.fonts = {}

        def font(self, size, bold=False):
            key = (size, bold)
            if key not in self.fonts:
                path = r"C:\Windows\Fonts\msyhbd.ttc" if bold else FONT_FILE
                self.fonts[key] = ImageFont.truetype(path, size * SS)
            return self.fonts[key]

        def _canvas(self, w, h):
            img = Image.new("RGBA", (w * SS, h * SS), (0, 0, 0, 0))
            return img, ImageDraw.Draw(img)

        def _finish(self, img, w, h):
            return ImageTk.PhotoImage(img.resize((w, h), Image.LANCZOS))

        def track(self, w, h, radius, fill):
            key = ("track", w, h, radius, fill)
            if key not in self.cache:
                img, d = self._canvas(w, h)
                d.rounded_rectangle([0, 0, w * SS - 1, h * SS - 1],
                                    radius=radius * SS, fill=fill)
                self.cache[key] = self._finish(img, w, h)
            return self.cache[key]

        def circle_btn(self, size, kind, state, accent=False):
            key = ("cbtn", size, kind, state, accent)
            if key in self.cache:
                return self.cache[key]
            img, d = self._canvas(size, size)
            s = size * SS
            if accent:
                fill = ACCENT_D if state == "hover" else ACCENT
                d.ellipse([0, 0, s - 1, s - 1], fill=fill)
                col = (255, 255, 255, 255)
            else:
                fill = BTN_A if state == "hover" else BTN
                d.ellipse([0, 0, s - 1, s - 1], fill=fill,
                          outline=(230, 232, 236, 255), width=int(SS * 0.8))
                col = (27, 31, 36, 255)
            self._glyph(d, s, kind, col)
            self.cache[key] = self._finish(img, size, size)
            return self.cache[key]

        def _glyph(self, d, s, kind, col):
            cx = cy = s / 2.0
            if kind == "play":
                d.polygon([(cx - s * .10, cy - s * .13), (cx + s * .14, cy),
                           (cx - s * .10, cy + s * .13)], fill=col)
            elif kind == "pause":
                w = s * .045
                d.rounded_rectangle([cx - s * .105, cy - s * .13, cx - s * .105 + w,
                                     cy + s * .13], radius=w / 2, fill=col)
                d.rounded_rectangle([cx + s * .06, cy - s * .13, cx + s * .06 + w,
                                     cy + s * .13], radius=w / 2, fill=col)
            elif kind == "prev":
                d.polygon([(cx + s * .10, cy - s * .12), (cx - s * .08, cy),
                           (cx + s * .10, cy + s * .12)], fill=col)
                d.rounded_rectangle([cx - s * .13, cy - s * .12, cx - s * .09,
                                     cy + s * .12], radius=s * .02, fill=col)
            elif kind == "next":
                d.polygon([(cx - s * .10, cy - s * .12), (cx + s * .08, cy),
                           (cx - s * .10, cy + s * .12)], fill=col)
                d.rounded_rectangle([cx + s * .09, cy - s * .12, cx + s * .13,
                                     cy + s * .12], radius=s * .02, fill=col)
            elif kind in ("back10", "fwd10"):
                sign = 1 if kind == "fwd10" else -1
                for off in (-s * .07, s * .07):
                    x = cx + off
                    d.polygon([(x - sign * s * .055, cy - s * .105),
                               (x + sign * s * .075, cy),
                               (x - sign * s * .055, cy + s * .105)], fill=col)

        def knob(self, d=18):
            key = ("knob", d)
            if key not in self.cache:
                img, dr = self._canvas(d, d)
                s = d * SS
                dr.ellipse([0, 0, s - 1, s - 1], fill=(255, 255, 255, 255),
                           outline=(37, 99, 235, 255), width=int(2.6 * SS))
                self.cache[key] = self._finish(img, d, d)
            return self.cache[key]

        def speaker(self, state="normal"):
            key = ("spk", state)
            if key in self.cache:
                return self.cache[key]
            img, d = self._canvas(24, 24)
            s = 24 * SS
            col = (226, 75, 74, 255) if state == "muted" else (91, 100, 112, 255)
            body = [(s * .14, s * .40), (s * .32, s * .40), (s * .52, s * .22),
                    (s * .52, s * .78), (s * .32, s * .60), (s * .14, s * .60)]
            d.polygon(body, fill=col)
            cx, cy = s * .54, s * .5
            if state == "muted":
                d.line([(cx + s * .06, cy - s * .10), (cx + s * .26, cy + s * .10)],
                       fill=col, width=int(1.7 * SS))
                d.line([(cx + s * .26, cy - s * .10), (cx + s * .06, cy + s * .10)],
                       fill=col, width=int(1.7 * SS))
            else:
                for r in (s * .12, s * .22):
                    d.arc([cx - r, cy - r, cx + r, cy + r], start=-55, end=55,
                          fill=col, width=int(1.5 * SS))
            self.cache[key] = self._finish(img, 24, 24)
            return self.cache[key]

        def pill(self, w, h, text, size, bg, fg, outline=None, state="normal"):
            key = ("pill", w, h, text, size, bg, fg, outline, state)
            if key in self.cache:
                return self.cache[key]
            img, d = self._canvas(w, h)
            if state == "hover" and not outline:
                bg = ACCENT_D
            d.rounded_rectangle([0, 0, w * SS - 1, h * SS - 1], radius=7 * SS,
                                fill=bg, outline=outline,
                                width=int(SS) if outline else 0)
            f = self.font(size)
            bb = d.textbbox((0, 0), text, font=f)
            tw, th = bb[2] - bb[0], bb[3] - bb[1]
            d.text(((w * SS - tw) / 2 - bb[0], (h * SS - th) / 2 - bb[1]), text,
                   font=f, fill=fg)
            self.cache[key] = self._finish(img, w, h)
            return self.cache[key]

    A = Assets()

    # ---------------- 控件 ----------------
    class CircleButton(tk.Canvas):
        def __init__(self, master, kind, command, size=42, accent=False, bg=BG):
            tk.Canvas.__init__(self, master, width=size, height=size, bg=bg,
                               highlightthickness=0, bd=0, cursor="hand2")
            self.kind, self.command, self.size, self.accent = kind, command, size, accent
            self.bind("<Button-1>", lambda e: self.command())
            self.bind("<Enter>", lambda e: self.repaint(True))
            self.bind("<Leave>", lambda e: self.repaint(False))
            self._hover = False
            self.repaint(False)

        def set_kind(self, kind):
            if kind != self.kind:
                self.kind = kind
                self.repaint(self._hover)

        def repaint(self, hover):
            self._hover = hover
            img = A.circle_btn(self.size, self.kind, "hover" if hover else "normal",
                               self.accent)
            self.delete("all")
            self.create_image(0, 0, image=img, anchor="nw")
            self.image = img

    class RoundedButton(tk.Canvas):
        def __init__(self, master, text, command, w=140, h=34, primary=False, size=10):
            tk.Canvas.__init__(self, master, width=w, height=h, bg=BG,
                               highlightthickness=0, bd=0, cursor="hand2")
            self.text, self.command, self.w, self.h = text, command, w, h
            self.primary, self.size = primary, size
            self.bind("<Button-1>", lambda e: self.command())
            self.bind("<Enter>", lambda e: self.repaint(True))
            self.bind("<Leave>", lambda e: self.repaint(False))
            self.repaint(False)

        def resize(self, w):
            if abs(w - self.w) > 1:
                self.w = w
                self.configure(width=w)
                self.repaint(False)

        def repaint(self, hover):
            if self.primary:
                img = A.pill(self.w, self.h, self.text, self.size,
                             (29, 78, 216, 255) if hover else (37, 99, 235, 255),
                             (255, 255, 255, 255))
            else:
                img = A.pill(self.w, self.h, self.text, self.size,
                             (230, 234, 241, 255) if hover else (242, 244, 248, 255),
                             (27, 31, 36, 255), outline=(224, 227, 232, 255))
            self.delete("all")
            self.create_image(0, 0, image=img, anchor="nw")
            self.image = img

    class Bar(tk.Canvas):
        """进度条：轨道与填充都用超采样素材，手柄为抗锯齿圆。"""

        def __init__(self, master, on_seek):
            tk.Canvas.__init__(self, master, height=24, bg=BG, highlightthickness=0, bd=0,
                               cursor="hand2")
            self.v = 0.0
            self.on_seek = on_seek
            self.hover = False
            self.bind("<Configure>", lambda e: self.redraw())
            self.bind("<Button-1>", self._press)
            self.bind("<B1-Motion>", self._press)
            self.bind("<Enter>", lambda e: (setattr(self, "hover", True), self.redraw()))
            self.bind("<Leave>", lambda e: (setattr(self, "hover", False), self.redraw()))

        def _press(self, e):
            w = self.winfo_width() or 1
            v = max(0.0, min(1.0, (e.x - 10) / max(1, w - 20)))
            self.v = v
            self.redraw()
            if self.on_seek:
                self.on_seek(v)

        def set(self, v):
            self.v = max(0.0, min(1.0, v))
            self.redraw()

        def redraw(self):
            self.delete("all")
            w = self.winfo_width() or 1
            if w < 20:
                return
            track = A.track(w, 10, 5, (229, 233, 240, 255))
            self.create_image(0, 12, image=track, anchor="w")
            self.track_img = track
            fw = int(round((w - 4) * self.v / 4.0) * 4)
            if fw >= 8:
                fill = A.track(fw, 10, 5, (37, 99, 235, 255))
                self.create_image(2, 12, image=fill, anchor="w")
                self.fill_img = fill
            x = 2 + max(9, min(w - 10, (w - 4) * self.v))
            kn = A.knob(18 if not self.hover else 20)
            self.create_image(x, 12, image=kn, anchor="center")
            self.knob_img = kn

    class Slider(tk.Canvas):
        def __init__(self, master, value=0, on_change=None):
            tk.Canvas.__init__(self, master, width=84, height=22, bg=BG,
                               highlightthickness=0, bd=0, cursor="hand2")
            self.value = value
            self.on_change = on_change
            self.bind("<Configure>", lambda e: self.redraw())
            self.bind("<Button-1>", self._press)
            self.bind("<B1-Motion>", self._press)

        def _press(self, e):
            w = self.winfo_width() or 1
            v = max(0, min(100, int(round((e.x - 7) / max(1, w - 14) * 100))))
            if v != self.value:
                self.value = v
                self.redraw()
                if self.on_change:
                    self.on_change(v)

        def set(self, v):
            self.value = int(v)
            self.redraw()

        def redraw(self):
            self.delete("all")
            w = self.winfo_width() or 1
            if w < 16:
                return
            self.create_image(0, 11, image=A.track(w, 6, 3, (229, 233, 240, 255)), anchor="w")
            fw = int(round((w - 4) * self.value / 100.0 / 2) * 2)
            if fw >= 6:
                self.create_image(2, 11, image=A.track(fw, 6, 3, (37, 99, 235, 255)),
                                  anchor="w")
            x = 2 + max(5, min(w - 6, (w - 4) * self.value / 100.0))
            self.create_image(x, 11, image=A.knob(12), anchor="center")

    class Playlist(tk.Canvas):
        ROW = 40

        def __init__(self, master, callbacks):
            tk.Canvas.__init__(self, master, bg=PANEL, highlightthickness=0, bd=0)
            self.items = []
            self.current = None
            self.selected = 0
            self.hover = None
            self.cb = callbacks
            self.drag_from = None
            self.drag_to = None
            self._press_y = 0
            self.bind("<Configure>", lambda e: self.redraw())
            self.bind("<Button-1>", self._press)
            self.bind("<B1-Motion>", self._motion)
            self.bind("<ButtonRelease-1>", self._release)
            self.bind("<Motion>", self._hover)
            self.bind("<Leave>", self._leave)
            self.bind("<Double-Button-1>", self._dbl)
            self.bind("<MouseWheel>", self._wheel)
            self.bind("<Button-4>", lambda e: self.yview_scroll(-1, "units"))
            self.bind("<Button-5>", lambda e: self.yview_scroll(1, "units"))

        def set_items(self, items, current):
            self.items = list(items)
            self.current = current
            if self.selected is None or self.selected >= len(self.items):
                self.selected = 0 if self.items else None
            self.redraw()

        def set_current(self, idx):
            self.current = idx
            if idx is not None:
                self.selected = idx
                self.see(idx)
            self.redraw()

        def set_selected(self, idx):
            if not self.items:
                return
            self.selected = max(0, min(idx, len(self.items) - 1))
            self.see(self.selected)
            self.redraw()

        def see(self, idx):
            self.update_idletasks()
            h = self.winfo_height()
            total = max(len(self.items) * self.ROW, 1)
            top = self.canvasy(0)
            y0, y1 = idx * self.ROW, (idx + 1) * self.ROW
            if y0 < top:
                self.yview_moveto(y0 / total)
            elif y1 > top + h:
                self.yview_moveto(max(0.0, (y1 - h) / total))

        def _index_at(self, y):
            i = int(self.canvasy(y) // self.ROW)
            return i if 0 <= i < len(self.items) else None

        def _press(self, e):
            i = self._index_at(e.y)
            if i is None:
                return
            w = self.winfo_width()
            if e.x >= w - 26:
                self.drag_from = self.drag_to = None    # 删除时不要残留拖动状态
                self.cb["delete"](i)
                return
            self.selected = i
            self.drag_from = i
            self._press_y = e.y
            self.cb["select"](i)
            self.redraw()

        def _motion(self, e):
            if self.drag_from is None:
                return
            if abs(e.y - self._press_y) < 8:
                return
            i = self._index_at(e.y)
            if i is None:
                i = len(self.items) - 1 if self.canvasy(e.y) > 0 else 0
            if i != self.drag_to:
                self.drag_to = i
                self.redraw()

        def _release(self, e):
            if self.drag_from is not None and self.drag_to is not None:
                if self.drag_to != self.drag_from:
                    self.cb["reorder"](self.drag_from, self.drag_to)
            self.drag_from = None
            self.drag_to = None
            self.redraw()

        def _hover(self, e):
            idx = self._index_at(e.y)
            if idx != self.hover:
                self.hover = idx
                self.redraw()

        def _leave(self, _e):
            if self.hover is not None:
                self.hover = None
                self.redraw()

        def _dbl(self, e):
            i = self._index_at(e.y)
            if i is not None:
                self.cb["play"](i)

        def _wheel(self, e):
            self.yview_scroll(int(-e.delta / 120), "units")

        def redraw(self):
            self.delete("all")
            self._imgs = []
            w = self.winfo_width() or 1
            if w < 40:
                return
            if not self.items:
                h = self.winfo_height() or 200
                cy = h / 2 - 14
                self.create_text(w / 2, cy, text="还没有添加视频", anchor="center",
                                 fill=SUB, font=(FONT, 10))
                self.create_text(w / 2, cy + 24, text="点下方按钮添加，或直接把文件夹拖进来",
                                 anchor="center", fill=TER, font=(FONT, 8))
                self.configure(scrollregion=(0, 0, w, max(h, 1)))
                return
            hl_w = w - 8
            for i, path in enumerate(self.items):
                y = i * self.ROW
                if i == self.drag_from and self.drag_to is not None:
                    continue
                if i == self.current:
                    img = A.track(hl_w, self.ROW - 4, 9, (232, 240, 254, 255))
                    self.create_image(4, y + 2, image=img, anchor="nw")
                    self._imgs.append(img)
                    self.create_rectangle(4, y + 10, 6, y + self.ROW - 10,
                                          fill=ACCENT, outline="")
                elif i == self.selected:
                    img = A.track(hl_w, self.ROW - 4, 9, (238, 241, 246, 255))
                    self.create_image(4, y + 2, image=img, anchor="nw")
                    self._imgs.append(img)
                elif i == self.hover:
                    img = A.track(hl_w, self.ROW - 4, 9, (243, 245, 248, 255))
                    self.create_image(4, y + 2, image=img, anchor="nw")
                    self._imgs.append(img)

                num_col = ACCENT if i == self.current else TER
                self.create_text(16, y + self.ROW / 2, text="%02d" % (i + 1), anchor="w",
                                 fill=num_col, font=(FONT, 8))
                name = os.path.basename(path)
                show_del = (i == self.hover and self.drag_from is None)
                right = 62 if not show_del else 80
                avail = max(40, w - 38 - right - 6)
                self.create_text(38, y + self.ROW / 2, text=fit_text(name, avail),
                                 anchor="w", fill=TEXT if i == self.current else SUB,
                                 font=(FONT, 10))
                try:
                    size = human_size(os.path.getsize(path))
                except OSError:
                    size = ""
                if not show_del:
                    self.create_text(w - 12, y + self.ROW / 2, text=size, anchor="e",
                                     fill=TER, font=(FONT, 8))
                if show_del:
                    cx, cy = w - 18, y + self.ROW / 2
                    self.create_oval(cx - 9, cy - 9, cx + 9, cy + 9, fill="#EBEEF3",
                                     outline="")
                    self.create_line(cx - 3.5, cy - 3.5, cx + 3.5, cy + 3.5,
                                     fill=SUB, width=1.4)
                    self.create_line(cx + 3.5, cy - 3.5, cx - 3.5, cy + 3.5,
                                     fill=SUB, width=1.4)

            if self.drag_to is not None:
                y = self.drag_to * self.ROW
                self.create_rectangle(8, y - 1, w - 8, y + 1, fill=ACCENT, outline="")

            self.configure(scrollregion=(0, 0, w, max(len(self.items) * self.ROW, 1)))

    def human_size(n):
        for unit in ("B", "KB", "MB", "GB"):
            if n < 1024 or unit == "GB":
                return ("%d %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
            n /= 1024.0
        return ""

    def fit_text(text, avail):
        f = tkfont.Font(family=FONT, size=10)
        if f.measure(text) <= avail:
            return text
        while text and f.measure(text + "…") > avail:
            text = text[:-1]
        return text + "…"

    # ---------------- 布局 ----------------
    body = tk.Frame(root, bg=BG)
    body.pack(fill="both", expand=True)
    body.columnconfigure(0, weight=1)
    body.columnconfigure(1, weight=0, minsize=326)
    body.rowconfigure(0, weight=1)

    left = tk.Frame(body, bg=BG)
    left.grid(row=0, column=0, sticky="nsew", padx=(28, 22), pady=(22, 16))

    right = tk.Frame(body, bg=PANEL, highlightbackground=BORDER, highlightthickness=1)
    right.grid(row=0, column=1, sticky="ns")

    bottom = tk.Frame(left, bg=BG)
    bottom.pack(side="bottom", fill="x", pady=(14, 0))
    tk.Frame(bottom, bg="#EDF0F4", height=1).pack(fill="x", pady=(0, 12))
    next_lbl = tk.Label(bottom, text="", font=(FONT, 9), bg=BG, fg=SUB, anchor="w")
    next_lbl.pack(side="left")
    rest_lbl = tk.Label(bottom, text="", font=(FONT, 8), bg=BG, fg=TER, anchor="e")
    rest_lbl.pack(side="right")

    head = tk.Frame(left, bg=BG)
    head.pack(fill="x")
    tk.Label(head, text="正在播放", font=(FONT, 9), bg=BG, fg=SUB).pack(side="left")
    state_lbl = tk.Label(head, text="未连接", font=(FONT, 9), bg=BG, fg=SUB)
    state_lbl.pack(side="right")

    title_lbl = tk.Label(left, text="未选择媒体", font=(FONT, 15, "bold"), bg=BG, fg=TEXT,
                         anchor="w", justify="left", wraplength=520)
    title_lbl.pack(fill="x", pady=(10, 0))
    meta_lbl = tk.Label(left, text="—", font=(FONT, 9), bg=BG, fg=SUB, anchor="w")
    meta_lbl.pack(fill="x", pady=(6, 0))

    prog = tk.Frame(left, bg=BG)
    prog.pack(fill="x", pady=(26, 0))
    bar = Bar(prog, on_seek=lambda f: seek_ratio(f))
    bar.pack(fill="x")
    trow = tk.Frame(prog, bg=BG)
    trow.pack(fill="x", pady=(4, 0))
    time_lbl = tk.Label(trow, text="00:00:00", font=("Consolas", 11, "bold"), bg=BG, fg=TEXT)
    time_lbl.pack(side="left")
    remain_lbl = tk.Label(trow, text="剩余 --:--", font=(FONT, 9), bg=BG, fg=TER)
    remain_lbl.pack(side="right")

    ctrl = tk.Frame(left, bg=BG)
    ctrl.pack(fill="x", pady=(30, 0))
    ctrl.columnconfigure(0, weight=1)
    ctrl.columnconfigure(2, weight=1)

    center = tk.Frame(ctrl, bg=BG)
    center.grid(row=0, column=1)

    b_back = CircleButton(center, "back10", lambda: seek(-10), size=42)
    b_prev = CircleButton(center, "prev", lambda: play_prev(), size=42)
    b_play = CircleButton(center, "play", lambda: toggle_play(), size=58, accent=True)
    b_next = CircleButton(center, "next", lambda: play_next(), size=42)
    b_fwd = CircleButton(center, "fwd10", lambda: seek(10), size=42)
    for i, b in enumerate((b_back, b_prev, b_play, b_next, b_fwd)):
        b.pack(side="left", padx=(0 if i == 0 else 8, 0))

    volw = tk.Frame(ctrl, bg=BG)
    volw.grid(row=0, column=2, sticky="e")
    mute_btn = tk.Canvas(volw, width=24, height=24, bg=BG, highlightthickness=0, bd=0,
                         cursor="hand2")
    mute_btn.pack(side="left", padx=(0, 8))
    mute_btn.bind("<Button-1>", lambda e: toggle_mute())
    vol = Slider(volw, value=0, on_change=lambda v: on_volume(v))
    vol.pack(side="left")

    def draw_mute():
        img = A.speaker("muted" if app["muted"] else "normal")
        mute_btn.delete("all")
        mute_btn.create_image(0, 0, image=img, anchor="nw")
        mute_btn.img = img

    # ---------------- 右栏 ----------------
    ph = tk.Frame(right, bg=PANEL)
    ph.pack(fill="x", padx=18, pady=(16, 8))
    tk.Label(ph, text="播放列表", font=(FONT, 10, "bold"), bg=PANEL, fg=TEXT).pack(side="left")
    count_lbl = tk.Label(ph, text="0 个", font=(FONT, 9), bg=PANEL, fg=SUB)
    count_lbl.pack(side="right")

    pb = tk.Frame(right, bg=PANEL)
    pb.pack(fill="both", expand=True, padx=(10, 6))
    plsb = tk.Scrollbar(pb, width=10)
    plsb.pack(side="right", fill="y")
    plist = Playlist(pb, {"play": lambda i: play_index(i),
                          "select": lambda i: None,
                          "delete": lambda i: delete_index(i),
                          "reorder": lambda a, b: reorder(a, b)})
    plist.pack(side="left", fill="both", expand=True)
    plsb.config(command=plist.yview)
    plist.config(yscrollcommand=plsb.set)

    pf = tk.Frame(right, bg=PANEL)
    pf.pack(fill="x", padx=18, pady=(10, 14))
    btn_add = RoundedButton(pf, "添加文件", lambda: add_files(), w=140, h=34)
    btn_add.pack(side="left")
    btn_dir = RoundedButton(pf, "添加文件夹", lambda: add_folder(), w=140, h=34)
    btn_dir.pack(side="left", padx=(8, 0))
    clear_lbl = tk.Label(pf, text="清空", font=(FONT, 9), bg=PANEL, fg=TER, cursor="hand2")
    clear_lbl.pack(side="right")
    clear_lbl.bind("<Button-1>", lambda e: clear_list())

    def layout_footer(_e=None):
        w = pf.winfo_width()
        if w > 40:
            each = max(90, (w - 52 - 8) // 2)
            btn_add.resize(each)
            btn_dir.resize(each)

    pf.bind("<Configure>", layout_footer)

    # ---------------- 状态栏 ----------------
    status = tk.Frame(root, bg=PANEL, height=34)
    status.pack(fill="x", side="bottom")
    status.pack_propagate(False)
    tk.Frame(status, bg=BORDER, height=1).pack(fill="x", side="top")

    dot = tk.Canvas(status, width=8, height=8, bg=PANEL, highlightthickness=0, bd=0)
    dot.pack(side="left", padx=(16, 7))
    dev_lbl = tk.Label(status, text="未连接", font=(FONT, 8), bg=PANEL, fg=SUB)
    dev_lbl.pack(side="left")
    speed_lbl = tk.Label(status, text="", font=(FONT, 8), bg=PANEL, fg=TER)
    speed_lbl.pack(side="left", padx=(10, 0))

    rec_lbl = tk.Label(status, text="重连", font=(FONT, 8), bg=PANEL, fg=TER, cursor="hand2")
    rec_lbl.pack(side="right", padx=(0, 16))
    log_lbl = tk.Label(status, text="日志", font=(FONT, 8), bg=PANEL, fg=TER, cursor="hand2")
    log_lbl.pack(side="right", padx=(0, 16))
    log_lbl.bind("<Button-1>", lambda e: toggle_log())
    rec_lbl.bind("<Button-1>", lambda e: do_connect())

    def set_dot(color):
        dot.delete("all")
        dot.create_oval(0, 0, 8, 8, fill=color, outline="")

    set_dot(TER)

    # ---------------- 行为 ----------------
    def ui_log(msg):
        if os.environ.get("PROJ_DEBUG"):
            print("[ui]", msg, flush=True)
        line = time.strftime("%H:%M:%S  ") + msg
        app["loglines"].append(line)
        if len(app["loglines"]) > 500:
            del app["loglines"][:100]
        win = app.get("logwin")
        if win and win.winfo_exists():
            win.text.configure(state="normal")
            win.text.insert("end", line + "\n")
            win.text.see("end")
            win.text.configure(state="disabled")

    def toggle_log():
        win = app.get("logwin")
        if win and win.winfo_exists():
            win.destroy()
            app["logwin"] = None
            return
        top = tk.Toplevel(root)
        top.title("日志")
        top.geometry("620x300")
        top.configure(bg=BG)
        txt = tk.Text(top, bg="#FBFCFD", fg=SUB, font=("Consolas", 9), relief="flat",
                      padx=12, pady=10)
        txt.pack(fill="both", expand=True)
        if app["loglines"]:
            txt.insert("end", "\n".join(app["loglines"]) + "\n")
            txt.see("end")
        txt.configure(state="disabled")
        top.text = txt
        app["logwin"] = top

    def _cb_error(exc, val, tb):
        try:
            with open(ERROR_LOG, "a", encoding="utf-8") as f:
                f.write(time.strftime("%Y-%m-%d %H:%M:%S\n")
                        + "".join(traceback.format_exception(exc, val, tb)) + "\n")
        except Exception:
            pass

    root.report_callback_exception = _cb_error

    def bg(fn, *a):
        def wrap():
            try:
                fn(*a)
            except Exception as e:
                post(lambda: ui_log("操作失败: %s" % e))
        threading.Thread(target=wrap, daemon=True).start()

    def need_device():
        if not app["proj"]:
            ui_log("还没连上投影仪，确认它已开机后点「重连」")
            return False
        return True

    def refresh_playlist():
        plist.set_items(app["playlist"], app["current_index"])
        count_lbl.config(text="%d 个" % len(app["playlist"]))
        idx = app["current_index"]
        if idx is not None and 0 <= idx < len(app["playlist"]):
            if idx + 1 < len(app["playlist"]):
                next_lbl.config(text="接下来  " + os.path.basename(app["playlist"][idx + 1]))
            else:
                next_lbl.config(text="已是最后一集")
            left_n = len(app["playlist"]) - idx - 1
            rest_lbl.config(text=("剩余 %d 集" % left_n) if left_n else "")
        else:
            next_lbl.config(text="添加视频后开始播放")
            rest_lbl.config(text="")

    def add_files():
        paths = filedialog.askopenfilenames(
            title="选择视频文件（可多选）",
            filetypes=[("视频文件", " ".join("*" + e for e in VIDEO_EXT)), ("所有文件", "*.*")])
        added = skipped = 0
        for p in paths:
            if not is_playable_file(p):
                skipped += 1
                continue
            if p not in app["playlist"]:
                app["playlist"].append(p)
                added += 1
        refresh_playlist()
        save_playlist(app["playlist"], app["current_index"])
        msg = "添加 %d 个文件，共 %d 个" % (added, len(app["playlist"]))
        if skipped:
            msg += "（跳过 %d 个空文件）" % skipped
        ui_log(msg)

    def add_folder():
        d = filedialog.askdirectory(title="选择包含视频的文件夹")
        if not d:
            return
        found = []
        skipped = 0
        for root_dir, _dirs, files in os.walk(d):
            for f in files:
                if f.lower().endswith(VIDEO_EXT):
                    full = os.path.join(root_dir, f)
                    if is_playable_file(full):
                        found.append(full)
                    else:
                        skipped += 1
        found.sort(key=lambda p: natural_key(os.path.relpath(p, d)))
        added = 0
        for p in found:
            if p not in app["playlist"]:
                app["playlist"].append(p)
                added += 1
        refresh_playlist()
        save_playlist(app["playlist"], app["current_index"])
        msg = "从文件夹加入 %d 个视频" % added
        if skipped:
            msg += "（跳过 %d 个空文件）" % skipped
        ui_log(msg)

    def clear_list():
        app["playlist"] = []
        app["current_index"] = None
        refresh_playlist()
        save_playlist([], None)
        ui_log("播放列表已清空")

    def delete_index(i):
        if not (0 <= i < len(app["playlist"])):
            return
        name = os.path.basename(app["playlist"].pop(i))
        if app["current_index"] is not None:
            if i == app["current_index"]:
                app["current_index"] = None
            elif i < app["current_index"]:
                app["current_index"] -= 1
        plist.selected = min(i, len(app["playlist"]) - 1) if app["playlist"] else None
        refresh_playlist()
        save_playlist(app["playlist"], app["current_index"])
        ui_log("已移除 %s" % name)

    def reorder(frm, to):
        if frm == to or not (0 <= frm < len(app["playlist"])):
            return
        item = app["playlist"].pop(frm)
        app["playlist"].insert(max(0, min(to, len(app["playlist"]))), item)
        cur = app["current_index"]
        if cur is not None:
            if cur == frm:
                cur = to
            elif frm < cur <= to:
                cur -= 1
            elif to <= cur < frm:
                cur += 1
            app["current_index"] = cur
        plist.selected = app["playlist"].index(item)
        refresh_playlist()
        save_playlist(app["playlist"], app["current_index"])
        ui_log("已调整顺序：%s 移到第 %d 位" % (os.path.basename(item), to + 1))

    def _connect_worker():
        p = find_projector(verbose=False)
        if not p:
            hint = missing_dlna_hint()
            post(lambda: (set_state("未连接", ERR), set_dot(ERR),
                          ui_log(hint or "没有找到投影仪")))
            return
        app["proj"] = p
        volume = 35
        try:
            volume = p.volume()
        except Exception:
            pass
        post(lambda: on_connected(p, volume))

    def on_connected(p, volume):
        dev_lbl.config(text="%s · %s" % (p.name or "未知设备", p.ip))
        meta_lbl.config(text=p.model or "")
        set_state("已连接", OK)
        set_dot(OK)
        app["prev_vol"] = volume
        vol.set(volume)
        ui_log("已连接 %s (%s:%d)" % (p.name, p.ip, p.port))

    def do_connect():
        set_state("连接中…", SUB)
        bg(_connect_worker)

    def set_state(text, color=SUB):
        state_lbl.config(text="● " + text, fg=color)

    def render_title():
        avail = max(200, left.winfo_width() - 10)
        text = app["title"]
        chosen = 12
        for size in (15, 14, 13, 12):
            f = tkfont.Font(family=FONT, size=size, weight="bold")
            if f.measure(text) <= avail * 2:
                chosen = size
                break
        title_lbl.config(font=(FONT, chosen, "bold"), wraplength=avail)

    def set_title(text):
        app["title"] = text
        title_lbl.config(text=text)
        render_title()

    left.bind("<Configure>", lambda e: render_title())

    def _cast_worker(path):
        proj = app["proj"]
        host = local_ip_for(proj.ip)
        if not app["server"]:
            app["server"] = MediaServer(host)
            port = app["server"].start()
            post(lambda: ui_log("媒体服务已启动 %s:%d" % (host, port)))
        url, mime = app["server"].url_for(path)
        proj.set_uri(url, mime, title=os.path.basename(path))
        proj.play()
        post(lambda: on_cast_started(path))
        if not verify_started(proj, app["server"]):
            post(lambda: ui_log("投影仪没来拉流：请在投影仪上按一下遥控器唤醒屏幕"))

    def on_cast_started(path):
        set_title(os.path.splitext(os.path.basename(path))[0])
        try:
            st = os.stat(path)
            meta_lbl.config(text="%s · %s" % (os.path.splitext(path)[1][1:].upper(),
                                              human_size(st.st_size)))
        except OSError:
            pass
        ui_log("已推送 %s" % os.path.basename(path))

    def play_index(idx):
        if not app["playlist"]:
            return
        idx = max(0, min(idx, len(app["playlist"]) - 1))
        if not need_device():
            return
        path = app["playlist"][idx]
        if not is_playable_file(path):
            ui_log("跳过空文件：%s" % os.path.basename(path))
            return
        app["current_index"] = idx
        app["state"] = ""
        app["max_pos"] = 0
        plist.set_current(idx)
        refresh_playlist()
        save_playlist(app["playlist"], idx)
        bg(_cast_worker, path)

    def play_selected():
        if not app["playlist"]:
            ui_log("播放列表是空的，先添加文件或文件夹")
            return
        play_index(plist.selected if plist.selected is not None else 0)

    def play_next():
        idx = app.get("current_index")
        if idx is None:
            play_selected()
            return
        if idx + 1 >= len(app["playlist"]):
            ui_log("已经是最后一集")
            return
        play_index(idx + 1)

    def play_prev():
        idx = app.get("current_index")
        if idx is None:
            return
        play_index(max(0, idx - 1))

    def toggle_play():
        if app["current_index"] is None:
            play_selected()
            return
        if not need_device():
            return
        playing = app["state"] == "PLAYING"
        bg(app["proj"].pause if playing else app["proj"].play)

    def _seek_worker(target):
        app["proj"].seek(target)
        post(lambda: ui_log("跳到 %s" % sec_to_hms(target)))

    def seek(delta):
        if not need_device():
            return
        target = max(0, min(max(app["total"] - 2, 0), app["cur"] + delta))
        bg(_seek_worker, target)

    def seek_ratio(r):
        if not need_device() or not app["total"]:
            return
        bg(_seek_worker, int(app["total"] * r))

    def on_volume(v):
        app["muted"] = False
        draw_mute()
        if app["proj"]:
            bg(app["proj"].set_volume, v)

    def toggle_mute():
        if not need_device():
            return
        if app["muted"]:
            app["muted"] = False
            v = app.get("prev_vol") or 35
            vol.set(v)
            bg(app["proj"].set_volume, v)
            ui_log("取消静音，音量 %d" % v)
        else:
            app["prev_vol"] = vol.value
            app["muted"] = True
            vol.set(0)
            bg(app["proj"].set_volume, 0)
            ui_log("已静音")
        draw_mute()

    def apply_state(st, cur, total, uri=""):
        prev = app.get("state") or ""
        app["cur"], app["total"], app["state"] = cur, total, st
        if st == "PLAYING":
            app["max_pos"] = max(app.get("max_pos") or 0, cur)
        label = {"PLAYING": "播放中", "PAUSED_PLAYBACK": "已暂停", "STOPPED": "已停止",
                 "TRANSITIONING": "缓冲中", "NO_MEDIA_PRESENT": "无媒体"}.get(st, st)
        set_state(label, OK if st == "PLAYING" else SUB)
        time_lbl.config(text=sec_to_hms(cur))
        remain_lbl.config(text=("剩余 " + sec_to_hms(max(total - cur, 0))) if total
                          else "剩余 --:--")
        bar.set((cur / total) if total else 0)
        b_play.set_kind("pause" if st == "PLAYING" else "play")

        reached_end = total > 0 and max(app.get("max_pos") or 0, cur) >= total - 3
        if (st == "STOPPED" and prev == "PLAYING" and reached_end
                and app.get("current_index") is not None):
            idx = app["current_index"]
            if idx + 1 < len(app["playlist"]):
                ui_log("本集结束，继续下一集")
                play_index(idx + 1)

    def _poll_worker():
        proj = app["proj"]
        try:
            st = proj.state()
            cur, total = proj.position()
        except Exception:
            post(lambda: (set_state("连接中断", ERR), set_dot(ERR)))
            app["polling"] = False
            return
        sent = app["server"].state.get("sent", 0) if app["server"] else 0
        post(lambda: apply_state(st, cur, total))
        post(lambda: on_speed(sent))
        app["polling"] = False

    def on_speed(sent):
        delta = sent - app.get("last_sent", 0)
        app["last_sent"] = sent
        rate = delta / 1024.0 / 1024.0 / 1.2
        if rate > 0.05:
            speed_lbl.config(text="%.1f MB/s" % rate)
        elif app["state"] != "PLAYING":
            speed_lbl.config(text="")

    def poll():
        if app["closing"]:
            return
        if app["proj"] and not app["polling"]:
            app["polling"] = True
            threading.Thread(target=_poll_worker, daemon=True).start()
        root.after(1200, poll)

    def on_close():
        app["closing"] = True
        save_playlist(app["playlist"], app["current_index"])
        proj, server = app["proj"], app["server"]

        def safe_stop():
            try:
                if proj:
                    proj.stop()
            except Exception:
                pass
            try:
                if server:
                    server.stop()
            except Exception:
                pass

        t = threading.Thread(target=safe_stop, daemon=True)
        t.start()
        t.join(1.5)
        root.destroy()

    def on_key(e):
        k = e.keysym
        if k == "space":
            toggle_play()
        elif k == "Up" and plist.selected is not None:
            plist.set_selected(plist.selected - 1)
        elif k == "Down" and plist.selected is not None:
            plist.set_selected(plist.selected + 1)
        elif k == "Return":
            play_selected()
        elif k == "Delete" and plist.selected is not None:
            delete_index(plist.selected)

    root.bind("<space>", on_key)
    root.bind("<Up>", on_key)
    root.bind("<Down>", on_key)
    root.bind("<Return>", on_key)
    root.bind("<Delete>", on_key)
    root.protocol("WM_DELETE_WINDOW", on_close)

    draw_mute()
    items, current, dropped = load_playlist()
    if items:
        app["playlist"], app["current_index"] = items, current
        ui_log("已恢复播放列表 %d 个" % len(items) + ("（跳过 %d 个失效文件）" % dropped
                                                      if dropped else ""))
        if dropped:
            save_playlist(items, current)     # 剔除失效项后立刻回写，保持文件干净
    refresh_playlist()
    root.after(60, drain)
    root.after(300, do_connect)
    root.after(1400, poll)
    root.mainloop()


# ---------------------------------------------------------------- 入口

if __name__ == "__main__":
    argv = sys.argv[1:]
    if "--gui" in argv or not argv:
        run_gui()
    else:
        sys.exit(cli(argv))
