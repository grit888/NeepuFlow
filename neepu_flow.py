# -*- coding: utf-8 -*-
"""
NeepuFlow - 东北电力大学 宿舍宽带(NEEPU-STU) 自动认证工具

仿 Campus-Flow 的思路，但改成"自己发现门户"，因此不绑定任何学校/运营商。
纯 Python 标准库（tkinter + urllib），零第三方依赖。

用法:
    python neepu_flow.py              # 打开设置界面
    python neepu_flow.py --daemon     # 后台静默运行（开机自启用这个）
    python neepu_flow.py --selftest   # 自检
    python neepu_flow.py --probe      # 只探测门户并打印结果
"""

import os
import re
import sys
import json
import glob
import time
import ssl
import random
import socket
import base64
import ctypes
import hashlib
import argparse
import threading
import datetime
import subprocess
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error
from html.parser import HTMLParser

APP_NAME = "NeepuFlow"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
LOG_PATH = os.path.join(BASE_DIR, "neepu_flow.log")
DUMP_DIR = os.path.join(BASE_DIR, "dump")

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

DEFAULT_CONFIG = {
    "username": "",
    "password": "",
    "operator": "移动",
    "target_ssid": "NEEPU-STU",
    "enabled": True,
    "portal_url": "",
    "portal_fallback": "http://202.198.8.232/",      # 东电 Panabit 认证门户（自动发现失败时兜底）
    "probe_url": "http://connect.rom.miui.com/generate_204",
    "expect": "",
    "success_keywords": "登录成功|认证成功|注销|已登录|已经登录|success|Success|上网",
    "fail_keywords": "密码错误|账号不存在|认证失败|用户名或密码|错误|失败|invalid",
    "check_seconds": 60,
    "online_check_seconds": 300,
    "night_mode": False,
    "verify_tls": False,
    "manual_first": False,
    "manual_url": "",
    "manual_fields": "",
    "panabit": True,               # 东电宿舍宽带（Panabit 网关）专用接口，默认开
}

OPERATOR_HINTS = {
    "移动": ["移动", "cmcc", "mobile", "mob"],
    "联通": ["联通", "unicom", "cucc"],
    "电信": ["电信", "telecom", "chinanet", "ctcc"],
    "校园网": ["校园", "校园网", "xn", "local", "本地"],
    "自动": [],
}
OPERATOR_SUFFIX = {"移动": "cmcc", "联通": "unicom", "电信": "telecom", "校园网": "xn", "自动": ""}

PROBE_FALLBACKS = [
    "http://www.msftconnecttest.com/redirect",       # 东电 Panabit 实测拦的就是这个
    "http://www.msftconnecttest.com/connecttest.txt",
    "http://connect.rom.miui.com/generate_204",
    "http://www.gstatic.com/generate_204",
    "http://captive.apple.com/hotspot-detect.html",
]

GUI_AUTOCLOSE = False        # --guitest 用：开窗后自动关闭


# ---------------------------------------------------------------- 日志

class Logger(object):
    def __init__(self, path=None):
        self.path = path or LOG_PATH
        self.queue = []          # GUI 轮询用
        self._lock = threading.Lock()
        self.quiet_console = False

    def __call__(self, msg):
        line = "%s  %s" % (datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), msg)
        with self._lock:
            try:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
            self.queue.append(line)
            if len(self.queue) > 2000:
                del self.queue[:1000]
        if not self.quiet_console:
            try:
                print(line)
            except Exception:
                pass

    def tail(self, n=400):
        with self._lock:
            return list(self.queue[-n:])


LOG = Logger()


# ---------------------------------------------------------------- DPAPI 凭据加密

class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.POINTER(ctypes.c_char))]


def _blob_bytes(blob):
    return ctypes.string_at(blob.pbData, blob.cbData)


def _dpapi(data, protect):
    """CryptProtectData / CryptUnprotectData —— 两者都是 7 个参数！
       (pDataIn, ppszDataDescr, pOptionalEntropy, pvReserved, pPromptStruct, dwFlags, pDataOut)
       少传一个会让 ctypes 读越界，进程直接 0xC0000409 fail-fast。"""
    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    blob_in = _DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    blob_out = _DATA_BLOB()
    if protect:
        ok = crypt32.CryptProtectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    else:
        ok = crypt32.CryptUnprotectData(
            ctypes.byref(blob_in), None, None, None, None, 0, ctypes.byref(blob_out))
    if not ok:
        raise OSError("DPAPI 调用失败")
    try:
        return _blob_bytes(blob_out)
    finally:
        kernel32.LocalFree(blob_out.pbData)


def enc_secret(text):
    if not text:
        return ""
    try:
        return "dpapi:" + base64.b64encode(_dpapi(text.encode("utf-8"), True)).decode("ascii")
    except Exception:
        key = (os.environ.get("USERNAME", "u") + "NeepuFlow").encode("utf-8")
        raw = text.encode("utf-8")
        return "weak:" + base64.b64encode(bytes(bytearray(
            b ^ key[i % len(key)] for i, b in enumerate(bytearray(raw))))).decode("ascii")


def dec_secret(text):
    if not text:
        return ""
    try:
        if text.startswith("dpapi:"):
            return _dpapi(base64.b64decode(text[6:]), False).decode("utf-8")
        if text.startswith("weak:"):
            key = (os.environ.get("USERNAME", "u") + "NeepuFlow").encode("utf-8")
            raw = base64.b64decode(text[5:])
            return bytes(bytearray(
                b ^ key[i % len(key)] for i, b in enumerate(bytearray(raw)))).decode("utf-8")
    except Exception:
        return ""
    return text


# ---------------------------------------------------------------- 配置

class Config(object):
    def __init__(self):
        self.data = dict(DEFAULT_CONFIG)

    def load(self):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                raw = json.load(f)
            for k in DEFAULT_CONFIG:
                if k in raw:
                    self.data[k] = raw[k]
            self.data["password"] = dec_secret(raw.get("password_enc", ""))
        except FileNotFoundError:
            pass
        except Exception as e:
            LOG("读取配置失败：%r" % (e,))
        return self

    def save(self):
        out = dict(self.data)
        out["password_enc"] = enc_secret(self.data.get("password", ""))
        out.pop("password", None)
        try:
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(out, f, ensure_ascii=False, indent=2)
            return True
        except Exception as e:
            LOG("保存配置失败：%r" % (e,))
            return False

    def __getitem__(self, k):
        return self.data.get(k, DEFAULT_CONFIG.get(k))

    def __setitem__(self, k, v):
        self.data[k] = v


# ---------------------------------------------------------------- HTML 表单解析

class _FormParser(HTMLParser):
    def __init__(self):
        HTMLParser.__init__(self, convert_charrefs=True)
        self.forms = []
        self._form = None
        self._select = None
        self._option = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._form = {
                "action": a.get("action", "") or "",
                "method": (a.get("method") or "post").lower(),
                "inputs": [],
                "selects": [],
            }
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({
                "name": a.get("name", "") or "",
                "type": (a.get("type") or "text").lower(),
                "value": a.get("value", "") or "",
                "id": a.get("id", "") or "",
            })
        elif tag == "select" and self._form is not None:
            self._select = {"name": a.get("name", "") or "", "id": a.get("id", "") or "",
                            "options": [], "value": ""}
            self._form["selects"].append(self._select)
        elif tag == "option" and self._select is not None:
            self._option = {"value": a.get("value", "") or "", "text": "",
                            "selected": "selected" in a}
        elif tag == "textarea" and self._form is not None:
            self._form["inputs"].append({"name": a.get("name", "") or "", "type": "textarea",
                                         "value": "", "id": a.get("id", "") or ""})

    def handle_data(self, data):
        if self._option is not None:
            self._option["text"] += data

    def handle_endtag(self, tag):
        if tag == "option" and self._option is not None:
            if self._select is not None:
                if not self._option["value"]:
                    self._option["value"] = self._option["text"].strip()
                self._option["text"] = self._option["text"].strip()
                self._select["options"].append(self._option)
                if self._option["selected"] and not self._select["value"]:
                    self._select["value"] = self._option["value"]
            self._option = None
        elif tag == "select":
            self._select = None
        elif tag == "form":
            self._form = None


def parse_forms(html):
    p = _FormParser()
    try:
        p.feed(html)
        p.close()
    except Exception:
        pass
    return p.forms


USER_HINTS = ["user", "account", "login", "name", "zhanghao", "yonghu", "账号", "用户名", "帐号"]
PWD_HINTS = ["pass", "pwd", "mima", "secret", "密码"]
SKIP_HINTS = ["captcha", "verify", "checkcode", "code", "vcode", "yzm", "验证码"]


def pick_login_form(forms):
    """挑出含密码框的表单"""
    for f in forms:
        for i in f["inputs"]:
            if i["type"] == "password" and i["name"]:
                return f
    for f in forms:
        if f["inputs"]:
            return f
    return None


def map_fields(form):
    """返回 (用户名name, 密码name, 隐藏字段dict)"""
    user_field, pwd_field = None, None
    extras = {}
    inputs = form["inputs"]
    for i in inputs:
        n, t = i["name"], i["type"]
        if not n:
            continue
        hint = (n + " " + i.get("id", "")).lower()
        if t == "password":
            if pwd_field is None:
                pwd_field = n
            continue
        if t == "hidden":
            extras[n] = i["value"]
            continue
        if any(h in hint for h in SKIP_HINTS):
            continue
        if any(h in hint for h in USER_HINTS) and user_field is None:
            user_field = n
    if user_field is None:
        for i in inputs:
            n, t = i["name"], i["type"]
            if not n or t in ("hidden", "password", "submit", "button", "checkbox", "radio"):
                continue
            hint = (n + " " + i.get("id", "")).lower()
            if any(h in hint for h in SKIP_HINTS):
                continue
            user_field = n
            break
    return user_field, pwd_field, extras


def find_operator_select(form):
    for s in form["selects"]:
        blob = (s["name"] + " " + s["id"] + " " + " ".join(
            (o["text"] + " " + o["value"]) for o in s["options"])).lower()
        for op, hints in OPERATOR_HINTS.items():
            if op == "自动":
                continue
            for h in hints:
                if h in blob:
                    return s
    return None


# ---------------------------------------------------------------- 网络

if hasattr(ssl, "_create_unverified_context"):
    _UNVERIFIED = ssl._create_unverified_context()
else:
    _UNVERIFIED = None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def make_opener(cookiejar=None, no_redirect=False, verify_tls=False):
    handlers = [urllib.request.ProxyHandler({})]        # 校园网必须直连，绕过系统代理
    if no_redirect:
        handlers.append(_NoRedirect())
    if cookiejar is not None:
        handlers.append(urllib.request.HTTPCookieProcessor(cookiejar))
    if not verify_tls and _UNVERIFIED is not None:
        handlers.append(urllib.request.HTTPSHandler(context=_UNVERIFIED))
    op = urllib.request.build_opener(*handlers)
    op.addheaders = [("User-Agent", UA), ("Accept", "*/*"),
                     ("Accept-Language", "zh-CN,zh;q=0.9")]
    return op


def http_get(url, cookiejar=None, timeout=10, no_redirect=False, verify_tls=False):
    op = make_opener(cookiejar, no_redirect, verify_tls)
    resp = op.open(url, timeout=timeout)
    body = resp.read()
    enc = "utf-8"
    ctype = resp.headers.get("Content-Type", "") or ""
    m = re.search(r"charset=([\w\-]+)", ctype, re.I)
    if m:
        enc = m.group(1)
    try:
        text = body.decode(enc, "replace")
    except Exception:
        text = body.decode("utf-8", "replace")
    return resp.geturl(), resp.status, dict(resp.headers), text


def _decode_console(raw):
    """netsh 输出在不同控制台可能是 UTF-8 或 GBK，挑中文没乱码的那个"""
    cands = []
    for enc in ("utf-8", "gbk"):
        try:
            cands.append(raw.decode(enc))
        except Exception:
            pass
    for t in cands:
        if "名称" in t or "状态" in t:
            return t
    return cands[0] if cands else raw.decode("utf-8", "replace")


def current_ssid():
    """当前连接的 Wi-Fi 名称；没连无线返回空串"""
    try:
        p = subprocess.run("netsh wlan show interfaces", shell=True,
                           capture_output=True, timeout=20)
        text = _decode_console(p.stdout)
    except Exception:
        return ""
    m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", text, re.M)
    if m:
        return m.group(1).strip()
    return ""


def ssid_ok(cfg):
    """(是否在目标网络, 说明)"""
    target = (cfg["target_ssid"] or "").strip()
    cur = current_ssid()
    if not target:
        return True, cur or "(未连无线)"
    if not cur:
        return False, "未连接任何无线网络"
    if cur.lower() == target.lower():
        return True, cur
    return False, "当前连的是「%s」，不是「%s」" % (cur, target)


def is_online(cfg, timeout=6):
    """联网检测：204 / 命中期望内容 / 命中在线特征 → 在线"""
    expect = (cfg["expect"] or "").strip()
    for url in [cfg["probe_url"]]:
        try:
            final, status, headers, text = http_get(
                url, timeout=timeout, no_redirect=True, verify_tls=cfg["verify_tls"])
            if status == 204:
                return True, "HTTP 204"
            if expect and expect in text:
                return True, "命中期望内容"
            if _looks_online(text):
                return True, "命中在线特征"
            return False, "HTTP %s 但内容不符" % status
        except urllib.error.HTTPError as e:
            # 302 到普通外网站点 = 这是正常联网；跳到认证网关才是没登录
            loc = e.headers.get("Location") or ""
            if loc and _is_internet_redirect(urllib.parse.urljoin(cfg["probe_url"], loc)):
                return True, "HTTP %s 跳转外网（已联网）" % e.code
            return False, "HTTP %s" % e.code
        except Exception as e:
            return False, "%s: %s" % (type(e).__name__, e)
    return False, "无法检测"


RE_META = re.compile(r'<meta[^>]+http-equiv\s*=\s*["\']?refresh["\']?[^>]*content\s*=\s*["\']?[^"\'>]*url\s*=\s*([^"\'>\s]+)', re.I)
RE_JS_LOC = re.compile(r'(?:window\.)?location(?:\.href|\.replace\s*\(|\s*=)\s*["\']([^"\']+)["\']', re.I)
RE_IFRAME = re.compile(r'<iframe[^>]+src\s*=\s*["\']([^"\']+)["\']', re.I)


def extract_redirect(text):
    for rx in (RE_META, RE_JS_LOC, RE_IFRAME):
        m = rx.search(text)
        if m:
            return m.group(1).strip()
    return None


def _looks_online(text):
    """识别"这是正常的联网探针响应"，避免把探针页误当成门户"""
    t = (text or "").strip()
    if len(t) == 0:
        return True
    low = t.lower()
    if "microsoft connect test" in low:
        return True
    if len(t) < 24 and low in ("success", "ok", "204", "true"):
        return True
    return False


RE_FORM_TAG = re.compile(r"<form\b", re.I)
RE_PWD_INPUT = re.compile(r"type\s*=\s*[\"']?password", re.I)


def _looks_like_portal(text):
    """有表单或有密码框才算门户；普通网页/探针响应不算"""
    if not text:
        return False
    return bool(RE_FORM_TAG.search(text) or RE_PWD_INPUT.search(text))


REDIRECT_BLOCKLIST = (
    "microsoft.com", "msftconnecttest.com", "msftncsi.com", "live.com",
    "google.com", "gstatic.com", "googleapis.com", "apple.com",
    "baidu.com", "miui.com", "xiaomi.com", "cloudflare.com",
    "mozilla.org", "firefox.com", "ubuntu.com", "debian.org",
    "qq.com", "taobao.com", "alibaba.com", "aliyun.com", "bilibili.com",
)


def _is_internet_redirect(url):
    """跳转目标是普通外网站点 → 这不是认证门户，是正常联网行为"""
    try:
        host = (urllib.parse.urlparse(url).hostname or "").lower()
    except Exception:
        return False
    if not host:
        return False
    for d in REDIRECT_BLOCKLIST:
        if host == d or host.endswith("." + d):
            return True
    return False


def discover_portal(cfg, timeout=8):
    """返回 (portal_url or None, 说明)

    优先级：HTTP 重定向 Location > 页面内跳转 > 被劫持的门户页。
    204 / 已知在线签名 / 没有表单的普通页面 一律跳过。
    """
    probes = [cfg["probe_url"]] + [u for u in PROBE_FALLBACKS if u != cfg["probe_url"]]
    seen = set()
    for url in probes:
        if url in seen:
            continue
        seen.add(url)
        try:
            final, status, headers, text = http_get(
                url, timeout=timeout, no_redirect=True, verify_tls=cfg["verify_tls"])
            if status == 204 or _looks_online(text):
                continue
            expect = (cfg["expect"] or "").strip()
            if expect and expect in text:
                continue
            hint = extract_redirect(text)
            if hint:
                target = urllib.parse.urljoin(url, hint)
                if not _is_internet_redirect(target):
                    return target, "从 %s 页面提取到跳转" % url
            if _looks_like_portal(text):
                return final, "探测地址被劫持到门户页：%s" % final
        except urllib.error.HTTPError as e:
            loc = e.headers.get("Location")
            if loc:
                target = urllib.parse.urljoin(url, loc)
                if not _is_internet_redirect(target):
                    return target, "HTTP %s 重定向" % e.code
                continue
            try:
                body = e.read().decode("utf-8", "replace")
            except Exception:
                body = ""
            if _looks_online(body):
                continue
            hint = extract_redirect(body) if body else None
            if hint:
                target = urllib.parse.urljoin(url, hint)
                if not _is_internet_redirect(target):
                    return target, "HTTP %s 页面内跳转" % e.code
            if _looks_like_portal(body):
                return (e.geturl() or url), "HTTP %s 返回门户页" % e.code
        except Exception:
            continue
    return None, "探测不到门户（可能已联网，或探测地址不可达）"


# ---------------------------------------------------------------- 东电 Panabit 门户（raasportal）
#
# 东电宿舍宽带（NEEPU-STU）的认证网关是 Panabit，门户是纯 JS 单页应用
# （raasportal），页面里根本没有 <form>，所以"解析表单 → POST"这条路走不通。
# 正确姿势是直接调它的 JSON 接口：
#
#     POST api/setacct.php  保存账号（门户自己也是先调这个）
#     POST api/login.php    提交认证，密码必须是 encode() 过的
#     POST api/ack_auth.php 认证确认
#     POST api/stat.php     轮询认证结果
#
# 而 encode() 是（门户 assets/js/crypto.js 解出来的）：
#     encode(pw) = hex( AES-128-ECB( 零填充( 4位随机盐 + 明文密码 ) ) )
#     key = "5a3b9f207411a8ed"      mode=ECB  padding=ZeroPadding
#
# 为了保持"零第三方依赖"，这里用纯标准库复刻了一份 AES-128 加密。
# 已与门户运行时逐字节比对一致（同一明文密文完全相同）。

AES_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
AES_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _aes_xtime(a):
    a <<= 1
    return (a ^ 0x1b) & 0xff if a & 0x100 else a


def _aes_mul(a, b):
    r = 0
    while b:
        if b & 1:
            r ^= a
        a = _aes_xtime(a)
        b >>= 1
    return r & 0xff


def _aes_expand_key(key):
    w = [list(key[i * 4:i * 4 + 4]) for i in range(4)]
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]
            t = [AES_SBOX[b] for b in t]
            t[0] ^= AES_RCON[i // 4 - 1]
        w.append([w[i - 4][j] ^ t[j] for j in range(4)])
    return [bytes([w[r * 4 + c][b] for c in range(4) for b in range(4)])
            for r in range(11)]


def _aes_encrypt_block(block, rk):
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 10):
        s = [AES_SBOX[b] for b in s]
        ns = list(s)
        for r in range(1, 4):                       # ShiftRows（列优先存储）
            col = [s[c * 4 + r] for c in range(4)]
            col = col[r:] + col[:r]
            for c in range(4):
                ns[c * 4 + r] = col[c]
        s = ns
        mc = []                                     # MixColumns
        for c in range(4):
            a = s[c * 4:c * 4 + 4]
            mc += [_aes_mul(a[0], 2) ^ _aes_mul(a[1], 3) ^ a[2] ^ a[3],
                   a[0] ^ _aes_mul(a[1], 2) ^ _aes_mul(a[2], 3) ^ a[3],
                   a[0] ^ a[1] ^ _aes_mul(a[2], 2) ^ _aes_mul(a[3], 3),
                   _aes_mul(a[0], 3) ^ a[1] ^ a[2] ^ _aes_mul(a[3], 2)]
        s = [mc[i] ^ rk[rnd][i] for i in range(16)]
    s = [AES_SBOX[b] for b in s]
    ns = list(s)
    for r in range(1, 4):
        col = [s[c * 4 + r] for c in range(4)]
        col = col[r:] + col[:r]
        for c in range(4):
            ns[c * 4 + r] = col[c]
    return bytes([ns[i] ^ rk[10][i] for i in range(16)])


def aes_ecb_hex(data, key):
    """AES-ECB + 零填充，返回十六进制字符串"""
    rk = _aes_expand_key(key)
    if len(data) % 16:
        data = data + b"\x00" * (16 - len(data) % 16)
    out = b""
    for i in range(0, len(data), 16):
        out += _aes_encrypt_block(data[i:i + 16], rk)
    return out.hex()


PANABIT_HOST = "202.198.8.232"                       # 东电认证网关
PANABIT_KEY = b"5a3b9f207411a8ed"                    # 门户 crypto.js 里的 AES 密钥
PANABIT_POOL = {"移动": "yidong", "联通": "liantong", "电信": "dianxin"}
PANABIT_SALT = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"


def panabit_encode(pw):
    """复刻门户 tp/school/js/index.js 的 encode()：4 位随机盐 + AES-128-ECB"""
    salt = "".join(random.choice(PANABIT_SALT) for _ in range(4))
    return aes_ecb_hex((salt + pw).encode("utf-8"), PANABIT_KEY)


def local_ip():
    """本机在校园网里的地址（不发包，只让系统选路由）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("202.198.8.232", 80))
        return s.getsockname()[0]
    except Exception:
        return ""
    finally:
        s.close()


def portal_reachable(host=PANABIT_HOST, port=80, timeout=1.5):
    """认证网关能不能连上（用来判断"是不是真的在 NEEPU-STU 上"）"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((host, port)) == 0
    except Exception:
        return False
    finally:
        s.close()


def panabit_params(cfg, log=None):
    """返回 (门户基址, 参数字典, 说明)。

    网关拦截外网请求时，会把浏览器 302 到门户并在 URL 上带一串本次会话参数
    （wlanuserip/clientip/wlanacname/clientmac/paip/vlan/iarmdst）。
    这里先用探针把那一串原样捞回来；捞不到再自造一份最小集合。
    """
    def _from_url(u, how):
        parsed = urllib.parse.urlparse(u)
        base = "%s://%s" % (parsed.scheme or "http", parsed.netloc)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        return base, params, how

    probes = [cfg["probe_url"]] + [u for u in PROBE_FALLBACKS if u != cfg["probe_url"]]
    seen = set()
    for url in probes:
        if not url or url in seen:
            continue
        seen.add(url)
        op = make_opener(no_redirect=True, verify_tls=cfg["verify_tls"])
        try:
            resp = op.open(url, timeout=6)
        except urllib.error.HTTPError as e:
            # 网关拦截外网请求 → 302 到门户，URL 上带着本次会话的全部参数
            loc = e.headers.get("Location") or ""
            if "wlanacname=" in loc or PANABIT_HOST in loc:
                return _from_url(loc, "探针被网关拦截：%s" % url)
            continue
        except Exception:
            continue
        # 没被拦：也可能网关直接把门户页塞回来了，翻一下正文
        try:
            final = resp.geturl()
            if "wlanacname=" in final:
                return _from_url(final, "探针被改写地址：%s" % url)
            head = resp.read(8192).decode("utf-8", "replace")
            if "raasportal" in head or "Panabit" in head:
                if "wlanacname=" in final:
                    return _from_url(final, "网关返回门户页：%s" % url)
                break                      # 是门户页但没带参数 → 走自造参数
        except Exception:
            pass

    # 兜底 1：配置里存过一个完整门户地址（含参数）
    saved = (cfg["portal_url"] or "").strip()
    if "wlanacname=" in saved:
        parsed = urllib.parse.urlparse(saved)
        params = {k: v[0] for k, v in urllib.parse.parse_qs(parsed.query).items()}
        # clientip 每次会话都会变。只有在真的能连上认证网关时才用本机当前地址覆盖，
        # 免得连的是手机热点却把热点地址当成校园网地址提交上去。
        ip = local_ip()
        if ip and portal_reachable():
            params["clientip"] = ip
            params["wlanuserip"] = ip
        else:
            params["wlanuserip"] = params.get("wlanuserip") or params.get("clientip") or ""
            params["clientip"] = params.get("clientip") or params["wlanuserip"]
        return "http://" + PANABIT_HOST, params, "沿用配置里保存的门户地址"

    # 兜底 2：自造最小参数（认证是按来源 IP 绑的，这三个够用）
    ip = local_ip()
    params = {"wlanuserip": ip, "clientip": ip, "wlanacname": "Panabit"}
    return "http://" + PANABIT_HOST, params, "自造参数（clientip=%s）" % ip


def panabit_post(base, path, params, body, cfg, timeout=15):
    """POST 门户的 JSON 接口，返回 (状态码, 文本)"""
    qs = urllib.parse.urlencode(params) if params else ""
    url = base + "/" + path + (("?" + qs) if qs else "")
    data = urllib.parse.urlencode(body or {}).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST", headers={
        "User-Agent": UA,
        "X-Requested-With": "XMLHttpRequest",
        "Referer": base + "/",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    })
    op = make_opener(verify_tls=cfg["verify_tls"])
    try:
        resp = op.open(req, timeout=timeout)
        return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""


def _json_field(text, key, default=None):
    try:
        return json.loads(text).get(key, default)
    except Exception:
        return default


PANABIT_RET_OK = (0,)                                # 0 = 成功
PANABIT_RET_ALREADY = (3, 121, 122)                  # 已经认证成功
PANABIT_RET_BADPWD = (4, 5)
PANABIT_RET_RETRY = (2,)                             # 正在认证 / 运营商侧还在同步


def panabit_login(cfg, log=None, params=None, base=None):
    """走 Panabit raasportal 的真实接口完成认证"""
    log = log or LOG
    user = (cfg["username"] or "").strip()
    pw = cfg["password"] or ""
    if not user or not pw:
        return AuthResult(False, "尚未填写账号或密码")

    pool = PANABIT_POOL.get(cfg["operator"], "yidong")
    if base is None or params is None:
        base, params, how = panabit_params(cfg, log)
        log("门户参数（%s）：%s" % (how, urllib.parse.urlencode(params)))
    else:
        log("门户参数：%s" % urllib.parse.urlencode(params))

    def body_for_login():
        return {"user": user, "pass": panabit_encode(pw), "code": "",
                "authmode": "0", "pool": pool, "isp_id": "0", "pxyacct": ""}

    # ① setacct：把账号存到门户（门户自己也是先调这个）
    try:
        st, txt = panabit_post(base, "api/setacct.php", params,
                              {"user": user, "pass": panabit_encode(pw), "pool": pool}, cfg)
        log("setacct.php → HTTP %s %s" % (st, (txt or "").strip()[:200]))
    except Exception as e:
        log("setacct.php 异常：%s: %s" % (type(e).__name__, e))

    # ② login：真正的认证提交
    login_body = body_for_login()
    try:
        st, txt = panabit_post(base, "api/login.php", params, login_body, cfg)
    except Exception as e:
        try:
            ok3, why3 = is_online(cfg)
        except Exception:
            ok3, why3 = False, ""
        if ok3:
            return AuthResult(True, "认证网关暂时不可达，但网络已在线（%s）" % why3)
        return AuthResult(False, "连不上认证网关 %s（%s）。多半是没连 NEEPU-STU，"
                                 "或者不在校园网里。" % (base, e))

    ret = _json_field(txt, "ret")
    msg = (_json_field(txt, "msg") or "").strip()
    if ret is None:
        # 返回的不是 JSON —— 已联网时网关的 api 代理会直接 502/拒绝，属正常
        try:
            ok2, why2 = is_online(cfg)
        except Exception:
            ok2, why2 = False, "未知"
        if ok2:
            return AuthResult(True, "门户接口不可用（%s），但网络已在线" % why2)
        return AuthResult(False, "认证接口返回异常：HTTP %s %s" % (st, (txt or "").strip()[:160]))
    log("login.php → ret=%s msg=%s" % (ret, msg))

    if ret in PANABIT_RET_BADPWD:
        hint = "运营商选错也会报这个" if ret == 4 else ""
        return AuthResult(False, "认证被拒（ret=%s）：%s %s" % (ret, msg, hint))

    if ret not in PANABIT_RET_OK and ret not in PANABIT_RET_ALREADY and ret not in PANABIT_RET_RETRY:
        return AuthResult(False, "认证失败（ret=%s）：%s" % (ret, msg or "门户未给出原因"))

    already = ret in PANABIT_RET_ALREADY

    # ③ ack_auth：确认认证（门户在 login 成功后立刻调它）
    try:
        st, txt = panabit_post(base, "api/ack_auth.php", params, login_body, cfg)
        log("ack_auth.php → HTTP %s %s" % (st, (txt or "").strip()[:120]))
    except Exception as e:
        log("ack_auth.php 异常：%s" % e)

    # ④ stat：轮询到出结果
    last = msg or "认证成功"
    for i in range(8):
        try:
            st, txt = panabit_post(base, "api/stat.php", params, login_body, cfg)
        except Exception as e:
            log("stat.php 异常：%s" % e)
            break
        r = _json_field(txt, "ret")
        m = (_json_field(txt, "msg") or "").strip()
        log("stat.php[%d] → ret=%s msg=%s" % (i, r, m))
        if m:
            last = m
        if r == 4:                       # 门户要求重新 ack 一次
            try:
                panabit_post(base, "api/ack_auth.php", params, login_body, cfg)
            except Exception:
                pass
        if r not in PANABIT_RET_RETRY and r not in PANABIT_RET_ALREADY:
            break
        time.sleep(1.5)

    # ⑤ 最后以"能不能真的上网"为准
    time.sleep(1.0)
    try:
        ok, why = is_online(cfg)
    except Exception:
        ok, why = False, "复检失败"
    if ok:
        if already:
            return AuthResult(True, "账号已在线上（%s）" % why)
        return AuthResult(True, "认证成功（%s）" % why)
    return AuthResult(False, "门户返回「%s」，但拨测仍未联网（%s）" % (last, why))


def panabit_logoff(cfg, log=None):
    """让网关把本机强制下线（"断网重连测试"用；平时不需要调）"""
    log = log or LOG
    try:
        base, params, how = panabit_params(cfg, log)
    except Exception as e:
        return False, "取门户参数失败：%s" % e
    for body in ({}, {"user": (cfg["username"] or "").strip()}):
        try:
            st, txt = panabit_post(base, "api/logoff.php", params, body, cfg)
        except Exception as e:
            return False, "%s: %s" % (type(e).__name__, e)
        log("logoff.php → HTTP %s %s" % (st, (txt or "").strip()[:200]))
        if _json_field(txt, "ret") == 0:
            return True, (_json_field(txt, "msg") or "下线成功").strip()
    return False, "门户未确认下线（可忽略，直接看重连结果）"


# ---------------------------------------------------------------- 认证

class AuthResult(object):
    def __init__(self, ok, message, detail=""):
        self.ok = ok
        self.message = message
        self.detail = detail

    def __repr__(self):
        return "<AuthResult ok=%s %s>" % (self.ok, self.message)


def _dump(name, content):
    try:
        os.makedirs(DUMP_DIR, exist_ok=True)
        stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        path = os.path.join(DUMP_DIR, "%s_%s.txt" % (name, stamp))
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path
    except Exception:
        return ""


def judge(cfg, text, wait=1.5):
    for kw in (cfg["fail_keywords"] or "").split("|"):
        kw = kw.strip()
        if kw and kw in text:
            return False, "命中失败关键字：%s" % kw
    for kw in (cfg["success_keywords"] or "").split("|"):
        kw = kw.strip()
        if kw and kw in text:
            return True, "命中成功关键字：%s" % kw
    if wait:
        time.sleep(wait)
    ok, why = is_online(cfg)
    if ok:
        return True, "复检已联网（%s）" % why
    return False, "未确认联网（%s）"


class Authenticator(object):
    def __init__(self, cfg, logger=None):
        self.cfg = cfg
        self.log = logger or LOG

    def _post(self, url, payload, method, cookiejar):
        op = make_opener(cookiejar, False, self.cfg["verify_tls"])
        data = urllib.parse.urlencode(payload).encode("utf-8")
        if method == "get":
            sep = "&" if "?" in url else "?"
            req = urllib.request.Request(url + sep + data.decode("utf-8"),
                                         headers={"User-Agent": UA})
            req.method = "GET"
        else:
            req = urllib.request.Request(
                url, data=data, headers={
                    "User-Agent": UA,
                    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                    "Referer": url,
                })
        resp = op.open(req, timeout=12)
        text = resp.read().decode("utf-8", "replace")
        return resp.geturl(), resp.status, text

    def _strategies(self, portal, user_field, pwd_field, extras, op_select, method):
        """产出若干 (名称, payload) 候选"""
        pw = self.cfg["password"] or ""
        ops = [("明文密码", pw)]
        md5 = hashlib.md5(pw.encode("utf-8")).hexdigest()
        if md5 != pw:
            ops.append(("MD5 密码", md5))

        select_val = ""
        if op_select is not None:
            hints = OPERATOR_HINTS.get(self.cfg["operator"], [])
            for o in op_select["options"]:
                blob = (o["text"] + " " + o["value"]).lower()
                if any(h.lower() in blob for h in hints):
                    select_val = o["value"]
                    break
            if not select_val and op_select["options"] and self.cfg["operator"] != "自动":
                select_val = op_select["value"] or op_select["options"][0]["value"]

        suffixes = [""]
        suf = OPERATOR_SUFFIX.get(self.cfg["operator"], "")
        if suf:
            suffixes.append("@" + suf)

        out = []
        for pname, pval in ops:
            for suf2 in suffixes:
                payload = dict(extras)
                payload[user_field] = (self.cfg["username"] or "") + suf2
                payload[pwd_field] = pval
                if op_select is not None and select_val:
                    payload[op_select["name"]] = select_val
                tag = "%s + %s" % (pname, ("用户名后缀 @%s" % suf2[1:]) if suf2 else "用户名原样")
                out.append((tag, payload))
        return out

    def try_login(self, log_detail=True):
        cfg = self.cfg
        if not cfg["username"] or not cfg["password"]:
            return AuthResult(False, "尚未填写账号或密码")

        ok, why = is_online(cfg)
        if ok:
            return AuthResult(True, "网络已在线，无需认证（%s）" % why)

        # 东电宿舍宽带（Panabit 网关）走专用接口，门户页面里没有表单可解析
        if self._is_panabit():
            self.log("识别到东电 Panabit 网关，走 raasportal 接口认证")
            return panabit_login(cfg, self.log)

        jar = http.cookiejar.CookieJar()
        portal = (cfg["portal_url"] or "").strip()

        if cfg["manual_first"] and cfg["manual_url"]:
            res = self._manual(jar)
            if res and res.ok:
                return res

        if not portal:
            portal, why = discover_portal(cfg)
            if portal:
                self.log("发现门户：%s（%s）" % (portal, why))
            else:
                fb = (cfg["portal_fallback"] or "").strip()
                if fb:
                    portal = fb
                    self.log("没探到门户（%s），改用备用地址：%s" % (why, fb))
                else:
                    inplace, sswhy = ssid_ok(cfg)
                    if not inplace:
                        return AuthResult(False, "找不到认证门户：%s。而且 %s" % (why, sswhy))
                    return AuthResult(False, "找不到认证门户：%s（当前网络：%s）" % (why, sswhy))
            self.log("发现门户：%s（%s）" % (portal, why))

        try:
            final, status, headers, html = http_get(
                portal, cookiejar=jar, timeout=12, verify_tls=cfg["verify_tls"])
        except Exception as e:
            return AuthResult(False, "打开门户失败：%s: %s" % (type(e).__name__, e))

        if final != portal:
            self.log("门户跳转到：%s" % final)
        portal_final = final

        forms = parse_forms(html)
        form = pick_login_form(forms)
        if form is None:
            path = _dump("portal_noform", html)
            return AuthResult(False, "门户页里没找到登录表单（已存 %s）" % path)

        method = form["method"] if form["method"] in ("get", "post") else "post"
        action = form["action"] or portal_final
        if action.lower().startswith("javascript") or not action:
            action = portal_final
        action = urllib.parse.urljoin(portal_final, action)

        user_field, pwd_field, extras = map_fields(form)
        if not user_field or not pwd_field:
            path = _dump("portal_nofield", html)
            return AuthResult(False, "识别不出账号/密码字段（账号=%s 密码=%s，已存 %s）"
                              % (user_field, pwd_field, path))

        op_select = find_operator_select(form)
        self.log("表单识别：action=%s method=%s 账号字段=%s 密码字段=%s 隐藏域=%s 运营商选择=%s"
                 % (action, method.upper(), user_field, pwd_field,
                    list(extras.keys()), (op_select["name"] if op_select else "无")))
        if op_select is not None:
            self.log("运营商选项：%s" % [(o["text"], o["value"]) for o in op_select["options"]])
        if log_detail:
            _dump("portal_page", html)
            _dump("portal_form", json.dumps(forms, ensure_ascii=False, indent=2))

        last = None
        for tag, payload in self._strategies(portal_final, user_field, pwd_field,
                                             extras, op_select, method):
            safe = dict(payload)
            safe[pwd_field] = "***"
            self.log("尝试：%s" % tag)
            try:
                furl, st, text = self._post(action, payload, method, jar)
            except urllib.error.HTTPError as e:
                last = "HTTP %s" % e.code
                self.log("  提交失败：HTTP %s" % e.code)
                continue
            except Exception as e:
                last = "%s: %s" % (type(e).__name__, e)
                self.log("  提交异常：%s" % last)
                continue

            ok, why = judge(cfg, text)
            self.log("  结果：%s（%s）" % ("成功" if ok else "未成功", why))
            if ok:
                return AuthResult(True, "认证成功（%s）" % tag)
            snippet = re.sub(r"\s+", " ", text)[:200]
            self.log("  响应片段：%s" % snippet)

        if cfg["manual_url"] and cfg["manual_fields"] and not cfg["manual_first"]:
            res = self._manual(jar)
            if res and res.ok:
                return res

        return AuthResult(False, "所有方式都未成功，最后一次：%s" % (last or "无"))

    def _is_panabit(self):
        """本工具是给东电做的：只要没被显式关掉，就走 Panabit 专用接口"""
        if not self.cfg["panabit"]:
            return False
        for u in (self.cfg["portal_url"], self.cfg["portal_fallback"]):
            if u and PANABIT_HOST in u:
                return True
        # 门户地址被清空时也当 Panabit 处理（东电就这一套网关）
        return not (self.cfg["portal_url"] or "").strip()

    def _manual(self, jar):
        cfg = self.cfg
        url = (cfg["manual_url"] or "").strip()
        if not url:
            return None
        fields = {}
        for line in (cfg["manual_fields"] or "").splitlines():
            line = line.strip()
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            v = v.strip()
            v = v.replace("{username}", cfg["username"]).replace("{password}", cfg["password"])
            v = v.replace("{md5}", hashlib.md5((cfg["password"] or "").encode("utf-8")).hexdigest())
            fields[k.strip()] = v
        self.log("使用手动参数提交：%s" % url)
        try:
            furl, st, text = self._post(url, fields, "post", jar)
        except Exception as e:
            return AuthResult(False, "手动提交异常：%s: %s" % (type(e).__name__, e))
        ok, why = judge(cfg, text)
        if ok:
            return AuthResult(True, "手动参数认证成功")
        return AuthResult(False, "手动参数未成功（%s）" % why)


# ---------------------------------------------------------------- 后台工作线程

class Worker(threading.Thread):
    daemon = True

    def __init__(self, cfg, logger=None):
        threading.Thread.__init__(self, name="NeepuFlowWorker")
        self.cfg = cfg
        self.log = logger or LOG
        self._stop = threading.Event()
        self._last_ssid = ""

    def stop(self):
        self._stop.set()

    def run(self):
        self.log("后台线程启动（间隔 %ss，在线复查 %ss）"
                 % (self.cfg["check_seconds"], self.cfg["online_check_seconds"]))
        auth = Authenticator(self.cfg, self.log)
        while not self._stop.is_set():
            try:
                if not self.cfg["enabled"]:
                    self._stop.wait(5)
                    continue
                if self.cfg["night_mode"]:
                    h = datetime.datetime.now().hour
                    if 1 <= h < 6:
                        self._stop.wait(180)
                        continue

                if not self.cfg["username"] or not self.cfg["password"]:
                    self._stop.wait(60)          # 还没填账号，安静待命，别刷日志
                    continue

                inplace, sswhy = ssid_ok(self.cfg)
                if not inplace:
                    if self._last_ssid != sswhy:
                        self.log("不在校园网：%s —— 等切过去再认证" % sswhy)
                        self._last_ssid = sswhy
                    self._stop.wait(30)
                    continue
                if self._last_ssid:
                    self.log("已进入目标网络：%s" % sswhy)
                    self._last_ssid = ""

                ok, why = is_online(self.cfg)
                if ok:
                    self._stop.wait(int(self.cfg["online_check_seconds"]))
                    continue

                self.log("检测到未联网（%s），开始认证" % why)
                res = auth.try_login(log_detail=True)
                self.log("认证结果：%s" % res.message)
                if res.ok:
                    self._stop.wait(20)
                else:
                    self._stop.wait(int(self.cfg["check_seconds"]))
            except Exception as e:
                self.log("后台循环异常：%s: %s" % (type(e).__name__, e))
                self._stop.wait(30)
        self.log("后台线程已停止")


def single_instance_lock():
    """用文件锁避免重复后台（Windows 上用 msvcrt）"""
    try:
        import msvcrt
        f = open(os.path.join(BASE_DIR, ".lock"), "a+")
        msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
        return f
    except Exception:
        return None


# ---------------------------------------------------------------- 开机自启（启动文件夹）

def startup_dir():
    return os.path.join(os.environ.get("APPDATA", ""),
                        r"Microsoft\Windows\Start Menu\Programs\Startup")


def _version_of(path):
    """从路径里尽力解析版本号，用于排序"""
    m = re.search(r"[Pp]ython(\d)(\d+)(?:\D|$)", path)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    m = re.search(r"(\d+)\.(\d+)\.(\d+)", path)
    if m:
        return (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    m = re.search(r"(\d+)\.(\d+)", path)
    if m:
        return (int(m.group(1)), int(m.group(2)), 0)
    return (0, 0, 0)


def find_pythonw():
    """枚举本机所有 Python，返回 (pythonw路径, 版本元组)，**优先最新版本**"""
    dirs = []
    try:
        p = subprocess.run("py -0p", shell=True, capture_output=True, timeout=15)
        for line in p.stdout.decode("gbk", "replace").splitlines():
            line = line.strip()
            if not line.lower().endswith("python.exe"):
                continue
            path = line.split()[-1].strip().strip('"')
            dirs.append(os.path.dirname(path))
    except Exception:
        pass
    for pat in (r"C:\Users\*\AppData\Local\Programs\Python\Python3*",
                r"C:\Program Files\Python3*",
                r"C:\Python3*",
                r"C:\Users\*\AppData\Local\Programs\Python"):
        try:
            dirs.extend(glob.glob(pat))
        except Exception:
            pass
    d = os.path.dirname(sys.executable)
    if d:
        dirs.append(d)

    best = (None, (0, 0, 0))
    seen = set()
    for d in dirs:
        if not d or d in seen:
            continue
        seen.add(d)
        for name in ("pythonw.exe", "python.exe"):
            exe = os.path.join(d, name)
            if not os.path.exists(exe) or "WindowsApps" in exe:
                continue
            v = _version_of(exe)
            if v > best[1]:
                best = (exe, v)
            break
    return best


def pythonw_path():
    """开机自启要用的解释器：本机最新版 Python 的 pythonw.exe"""
    exe, ver = find_pythonw()
    return exe or sys.executable


def autostart_path():
    return os.path.join(startup_dir(), "NeepuFlow.vbs")


def autostart_enabled():
    return os.path.exists(autostart_path())


def set_autostart(on):
    p = autostart_path()
    try:
        if on:
            exe = pythonw_path()
            script = os.path.join(BASE_DIR, "neepu_flow.py")
            vbs = (
                'Set sh = CreateObject("WScript.Shell")\r\n'
                'sh.CurrentDirectory = "%s"\r\n'
                'sh.Run """%s"" ""%s"" --daemon", 0, False\r\n'
            ) % (BASE_DIR, exe, script)
            with open(p, "w", encoding="gbk", newline="\r\n") as f:
                f.write(vbs)
            return True, "已开启开机自启：%s" % p
        else:
            if os.path.exists(p):
                os.remove(p)
            return True, "已关闭开机自启"
    except Exception as e:
        return False, "设置失败：%s: %s" % (type(e).__name__, e)


# ---------------------------------------------------------------- 自检 / 命令行

def cmd_selftest():
    print("=" * 60)
    print("NeepuFlow 自检")
    print("=" * 60)
    print("Python      :", sys.version.split()[0], sys.executable)
    print("脚本目录    :", BASE_DIR)
    print("配置文件    :", CONFIG_PATH, "(存在)" if os.path.exists(CONFIG_PATH) else "(无)")

    try:
        import tkinter
        print("tkinter     : OK (%s)" % tkinter.TkVersion)
    except Exception as e:
        print("tkinter     : 不可用 ->", e)

    c = Config().load()
    try:
        enc = enc_secret("自检样本")
        print("凭据加密    :", "DPAPI OK" if enc.startswith("dpapi:") else "降级(XOR)")
        rt = dec_secret(enc)
        print("凭据往返    :", "OK" if rt == "自检样本" else "失败 -> %r" % (rt,))
    except Exception as e:
        print("凭据加解密  : 异常 %r" % (e,))
    print("已存密码    :", ("有（%d 字符密文）" % len(c["password"])) if c["password"] else "无")

    print("---- 东电 Panabit 接口自检 ----")
    try:
        mine = aes_ecb_hex(b"abcdTestPass123", PANABIT_KEY)
        want = "aed1cc13e22b30f6ca953b296a6d6d03"      # 门户 crypto.js 对同一明文的输出
        print("AES-128-ECB :", "OK（与门户逐字节一致）" if mine == want else "失败 -> %s" % mine)
    except Exception as e:
        print("AES-128-ECB : 异常 %r" % (e,))
    try:
        print("encode()    : %s（%d 位 hex）" % (panabit_encode("SamplePass"), 32))
    except Exception as e:
        print("encode()    : 异常 %r" % (e,))
    print("运营商映射  :", PANABIT_POOL, "| 当前：%s -> %s"
          % (c["operator"], PANABIT_POOL.get(c["operator"], "yidong")))
    try:
        base, params, how = panabit_params(c)
        print("门户参数    :", how)
        print("            :", urllib.parse.urlencode(params) or "(空)")
    except Exception as e:
        print("门户参数    : 异常 %r" % (e,))

    print("---- 联网检测 ----")
    ok, why = is_online(c)
    print("在线        :", ok, "|", why)

    print("---- 门户发现 ----")
    portal, why = discover_portal(c)
    print("门户        :", portal, "|", why)

    print("---- HTML 解析自测 ----")
    demo = """<html><body><form action="/login.do" method="post">
      <input type="hidden" name="wlanuserip" value="1.2.3.4">
      <input type="text" name="username" id="account">
      <input type="password" name="password">
      <select name="domain"><option value="0">校园网</option>
        <option value="1" selected>中国移动</option>
        <option value="2">中国联通</option></select>
      <input type="submit" value="登录"></form></body></html>"""
    forms = parse_forms(demo)
    f = pick_login_form(forms)
    if f:
        print("表单        : action=%s method=%s" % (f["action"], f["method"]))
        print("字段映射    :", map_fields(f))
        s = find_operator_select(f)
        print("运营商下拉  :", s["name"] if s else "无",
              [(o["text"], o["value"]) for o in s["options"]] if s else "")
    else:
        print("表单        : 解析失败")

    print("---- 自启状态 ----")
    print("开机自启    :", "已开启" if autostart_enabled() else "未开启")
    exe, ver = find_pythonw()
    print("自启解释器  :", exe, "→ 版本", ".".join(str(x) for x in ver))
    print("启动文件    :", autostart_path())
    print("=" * 60)


def cmd_login():
    """命令行立刻做一次真实认证（排查用）"""
    c = Config().load()
    LOG("=" * 50)
    LOG("NeepuFlow 手动认证 pid=%s 账号=%s 运营商=%s"
        % (os.getpid(), c["username"] or "未填", c["operator"]))
    res = Authenticator(c).try_login()
    LOG("结果：%s" % res.message)
    print(res.message)
    return 0 if res.ok else 1


def cmd_probe():
    c = Config().load()
    ok, why = is_online(c)
    print("在线：%s | %s" % (ok, why))
    try:
        base, params, how = panabit_params(c)
        print("Panabit 参数：%s" % how)
        print("            %s" % (urllib.parse.urlencode(params) or "(空)"))
    except Exception as e:
        print("Panabit 参数：异常 %r" % (e,))
    portal, why = discover_portal(c)
    print("门户：%s | %s" % (portal, why))
    if portal:
        try:
            final, st, hd, html = http_get(portal, timeout=12, verify_tls=c["verify_tls"])
            path = _dump("portal_page", html)
            print("最终地址：%s (HTTP %s)" % (final, st))
            print("页面已存：%s" % path)
            for f in parse_forms(html):
                print("  表单 action=%s method=%s 字段=%s 下拉=%s"
                      % (f["action"], f["method"],
                         [i["name"] + ":" + i["type"] for i in f["inputs"] if i["name"]],
                         [(s["name"], [o["text"] for o in s["options"]]) for s in f["selects"]]))
        except Exception as e:
            print("打开门户失败：%s: %s" % (type(e).__name__, e))


def cmd_daemon():
    lock = single_instance_lock()
    if lock is None:
        LOG("已有实例在运行，退出")
        return
    cfg = Config().load()
    LOG("=" * 50)
    LOG("NeepuFlow 后台启动 pid=%s" % os.getpid())
    w = Worker(cfg)
    w.start()
    try:
        while w.is_alive():
            w.join(5)
    except KeyboardInterrupt:
        w.stop()


# ---------------------------------------------------------------- GUI

def run_gui():
    import tkinter as tk
    from tkinter import ttk, messagebox, scrolledtext

    cfg = Config().load()
    LOG("界面启动 pid=%s  账号=%s" % (os.getpid(),
                                    ((cfg["username"] or "")[:3] + "***") if cfg["username"] else "未填"))
    root = tk.Tk()
    root.title("NeepuFlow · 东电宿舍宽带自动认证")
    root.geometry("760x560")
    root.minsize(700, 520)

    style = ttk.Style()
    try:
        style.theme_use("vista")
    except Exception:
        pass
    try:
        root.option_add("*Font", ("Microsoft YaHei UI", 9))
    except Exception:
        pass

    worker_holder = {"w": None, "lock": None}

    top = ttk.Frame(root, padding=(12, 10, 12, 4))
    top.pack(fill="x")
    status_var = tk.StringVar(value="就绪")
    net_var = tk.StringVar(value="")
    autostart_var = tk.BooleanVar(value=autostart_enabled())
    ttk.Label(top, textvariable=status_var, foreground="#185FA5").pack(side="left")
    ttk.Label(top, textvariable=net_var, foreground="#5b636e").pack(side="right")

    nb = ttk.Notebook(root)
    nb.pack(fill="both", expand=True, padx=12, pady=(4, 8))

    # ---- 基础设置
    p1 = ttk.Frame(nb, padding=14)
    nb.add(p1, text="  基础设置  ")
    v_user = tk.StringVar(value=cfg["username"])
    v_pass = tk.StringVar(value=cfg["password"])
    v_op = tk.StringVar(value=cfg["operator"])
    v_portal = tk.StringVar(value=cfg["portal_url"])

    def row(parent, label, widget, r):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", pady=7, padx=(0, 10))
        widget.grid(row=r, column=1, sticky="ew", pady=7)

    p1.columnconfigure(1, weight=1)
    row(p1, "宽带账号", ttk.Entry(p1, textvariable=v_user), 0)
    row(p1, "密码", ttk.Entry(p1, textvariable=v_pass, show="●"), 1)
    row(p1, "运营商", ttk.Combobox(p1, textvariable=v_op, state="readonly",
                                   values=["移动", "联通"]), 2)
    row(p1, "认证门户地址", ttk.Entry(p1, textvariable=v_portal), 3)
    ttk.Label(p1, text="运营商：宿舍宽带是移动就选移动、联通就选联通（选错会报「账号或密码不正确」）。\n"
                       "门户地址留空 = 每次自动发现（推荐）。",
              foreground="#5b636e", justify="left").grid(row=4, column=1, sticky="w", pady=(0, 12))

    def do_probe():
        def job():
            status_var.set("正在探测门户…")
            inplace, sswhy = ssid_ok(cfg)
            if not inplace:
                msg = "不在目标网络：%s —— 先连上校园网再探测" % sswhy
                status_var.set(msg)
                LOG(msg)
                return
            p, why = discover_portal(cfg)
            if p:
                v_portal.set(p)
                status_var.set("探测到门户：%s" % p)
                LOG("探测到门户：%s（%s）" % (p, why))
            else:
                msg = "未探测到门户：%s（当前网络：%s）" % (why, sswhy)
                status_var.set(msg)
                LOG(msg)
        threading.Thread(target=job, daemon=True).start()

    def do_grab():
        sync_from_ui()

        def job():
            status_var.set("正在抓取门户页…")
            inplace, sswhy = ssid_ok(cfg)
            if not inplace:
                msg = "不在目标网络：%s —— 先连上校园网再抓" % sswhy
                status_var.set(msg)
                LOG(msg)
                return
            portal, why = discover_portal(cfg)
            if not portal:
                portal = (cfg["portal_fallback"] or "").strip()
                if portal:
                    LOG("没探到门户（%s），改用备用地址 %s" % (why, portal))
            if not portal:
                msg = "探不到门户，也没有备用地址"
                status_var.set(msg)
                LOG(msg)
                return
            try:
                final, st, hd, html = http_get(portal, timeout=12, verify_tls=cfg["verify_tls"])
            except Exception as e:
                msg = "打开门户失败：%s: %s" % (type(e).__name__, e)
                status_var.set(msg)
                LOG(msg)
                return
            p1 = _dump("manual_portal_page", html)
            forms = parse_forms(html)
            p2 = _dump("manual_portal_forms", json.dumps(forms, ensure_ascii=False, indent=2))
            LOG("抓取成功：%s（HTTP %s，%d 字节）" % (final, st, len(html)))
            LOG("表单结构：%s" % json.dumps(forms, ensure_ascii=False)[:1500])
            msg = "抓好了 → dump\\%s" % os.path.basename(p1)
            status_var.set(msg)
            messagebox.showinfo("抓取门户页", msg + "\n\n把这个文件发我就行（不含密码）。")
        threading.Thread(target=job, daemon=True).start()

    def do_test():
        sync_from_ui()
        cfg.save()

        def job():
            status_var.set("正在测试…")
            online, why = is_online(cfg)
            if online:
                status_var.set("已在线，无需认证")
                messagebox.showinfo(
                    "测试",
                    "当前网络已经在线（%s），不需要认证。\n\n"
                    "自动认证只在「连上了 NEEPU-STU 但还没登录」时才会动作，\n"
                    "比如刚开机、刚连上无线、或者你手动下线之后。\n\n"
                    "想现在就实测一次，点右边的「断网重连测试」。" % why)
                return
            res = Authenticator(cfg).try_login()
            status_var.set(res.message)
            messagebox.showinfo("测试", res.message)
        threading.Thread(target=job, daemon=True).start()

    def do_reconnect():
        sync_from_ui()
        cfg.save()
        if not messagebox.askyesno(
                "断网重连测试",
                "这一步会先把你从宿舍宽带上强制下线，再让程序自动把你认证回来。\n\n"
                "· 正常情况：几秒内恢复上网\n"
                "· 万一失败：打开浏览器访问任意网站，用手动登录页登录即可\n\n"
                "现在做吗？"):
            return

        def job():
            status_var.set("正在下线…")
            ok, detail = panabit_logoff(cfg)
            LOG("下线结果：%s | %s" % (ok, detail))
            if ok:
                time.sleep(2)
            status_var.set("正在重新认证…")
            res = Authenticator(cfg).try_login()
            LOG("重连结果：%s" % res.message)
            status_var.set(res.message)
            messagebox.showinfo("断网重连测试", res.message)
        threading.Thread(target=job, daemon=True).start()

    def sync_from_ui():
        cfg["username"] = v_user.get().strip()
        cfg["password"] = v_pass.get()
        cfg["operator"] = v_op.get()
        cfg["portal_url"] = v_portal.get().strip()

    def do_save_enable():
        sync_from_ui()
        sync_adv_from_ui()
        cfg["enabled"] = True
        if cfg.save():
            start_worker()
            status_var.set("已保存并启用后台")
        else:
            status_var.set("保存失败")

    def start_worker():
        if worker_holder["w"] and worker_holder["w"].is_alive():
            worker_holder["w"].stop()
        if worker_holder["lock"] is None:
            lock = single_instance_lock()
            if lock is None:
                # 开机自启的那个 --daemon 已经在跑了，别再起一个重复认证
                LOG("已有 NeepuFlow 后台在运行（多半是开机自启那个），本次不另起")
                status_var.set("后台已在运行（开机自启那个）")
                return
            worker_holder["lock"] = lock
        w = Worker(cfg)
        worker_holder["w"] = w
        w.start()

    def do_stop():
        cfg["enabled"] = False
        cfg.save()
        if worker_holder["w"]:
            worker_holder["w"].stop()
        status_var.set("后台已停止")

    bf = ttk.Frame(p1)
    bf.grid(row=5, column=1, sticky="w", pady=(6, 0))
    ttk.Button(bf, text="一键探测门户", command=do_probe).pack(side="left", padx=(0, 8))
    ttk.Button(bf, text="抓取门户页", command=do_grab).pack(side="left", padx=(0, 8))
    ttk.Button(bf, text="测试登录", command=do_test).pack(side="left", padx=(0, 8))
    ttk.Button(bf, text="断网重连测试", command=do_reconnect).pack(side="left", padx=(0, 8))
    ttk.Button(bf, text="保存并启用", command=do_save_enable).pack(side="left", padx=(0, 8))
    ttk.Button(bf, text="停止后台", command=do_stop).pack(side="left")

    # ---- 高级设置
    p2 = ttk.Frame(nb, padding=14)
    nb.add(p2, text="  高级设置  ")
    v_probe = tk.StringVar(value=cfg["probe_url"])
    v_expect = tk.StringVar(value=cfg["expect"])
    v_succ = tk.StringVar(value=cfg["success_keywords"])
    v_ck = tk.StringVar(value=str(cfg["check_seconds"]))
    v_ock = tk.StringVar(value=str(cfg["online_check_seconds"]))
    v_ssid = tk.StringVar(value=cfg["target_ssid"])
    v_night = tk.BooleanVar(value=bool(cfg["night_mode"]))
    v_mfirst = tk.BooleanVar(value=bool(cfg["manual_first"]))
    v_murl = tk.StringVar(value=cfg["manual_url"])

    p2.columnconfigure(1, weight=1)
    row(p2, "联网检测地址", ttk.Entry(p2, textvariable=v_probe), 0)
    row(p2, "检测成功内容", ttk.Entry(p2, textvariable=v_expect), 1)
    row(p2, "成功关键字", ttk.Entry(p2, textvariable=v_succ), 2)
    row(p2, "离线检查间隔(秒)", ttk.Entry(p2, textvariable=v_ck), 3)
    row(p2, "在线复查间隔(秒)", ttk.Entry(p2, textvariable=v_ock), 4)
    row(p2, "目标 Wi-Fi 名称", ttk.Entry(p2, textvariable=v_ssid), 5)
    ttk.Label(p2, text="↑ 不在这个 Wi-Fi 上就不认证（留空 = 不限）。默认 NEEPU-STU",
              foreground="#5b636e").grid(row=6, column=1, sticky="w", pady=(0, 6))
    row(p2, "手动提交地址", ttk.Entry(p2, textvariable=v_murl), 7)
    ttk.Label(p2, text="附加字段（每行 key=value，可用 {username} {password} {md5} 占位）",
              foreground="#5b636e").grid(row=8, column=0, columnspan=2, sticky="w", pady=(10, 2))
    txt_fields = scrolledtext.ScrolledText(p2, height=5, wrap="none")
    txt_fields.grid(row=9, column=0, columnspan=2, sticky="nsew")
    txt_fields.insert("1.0", cfg["manual_fields"])
    p2.rowconfigure(9, weight=1)
    chk = ttk.Frame(p2)
    chk.grid(row=10, column=0, columnspan=2, sticky="w", pady=(8, 0))
    ttk.Checkbutton(chk, text="夜间静默（1:00-6:00 不认证）", variable=v_night).pack(side="left", padx=(0, 16))
    ttk.Checkbutton(chk, text="优先使用手动参数", variable=v_mfirst).pack(side="left")

    def sync_adv_from_ui():
        cfg["probe_url"] = v_probe.get().strip() or DEFAULT_CONFIG["probe_url"]
        cfg["expect"] = v_expect.get().strip()
        cfg["success_keywords"] = v_succ.get().strip()
        cfg["target_ssid"] = v_ssid.get().strip()
        for key, var in (("check_seconds", v_ck), ("online_check_seconds", v_ock)):
            try:
                cfg[key] = max(15, int(var.get()))
            except Exception:
                pass
        cfg["night_mode"] = bool(v_night.get())
        cfg["manual_first"] = bool(v_mfirst.get())
        cfg["manual_url"] = v_murl.get().strip()
        cfg["manual_fields"] = txt_fields.get("1.0", "end").strip()

    def do_save_adv():
        sync_adv_from_ui()
        cfg.save()
        status_var.set("高级设置已保存")

    af = ttk.Frame(p2)
    af.grid(row=11, column=0, columnspan=2, sticky="w", pady=(10, 0))
    ttk.Button(af, text="保存设置", command=do_save_adv).pack(side="left", padx=(0, 8))
    ttk.Button(af, text="打开程序目录",
               command=lambda: os.startfile(BASE_DIR)).pack(side="left", padx=(0, 8))
    ttk.Button(af, text="恢复默认",
               command=lambda: (cfg.data.update(DEFAULT_CONFIG), cfg.save(),
                                messagebox.showinfo("NeepuFlow", "已恢复默认，请重开窗口"))).pack(side="left")

    # ---- 日志
    p3 = ttk.Frame(nb, padding=10)
    nb.add(p3, text="  运行日志  ")
    logbox = scrolledtext.ScrolledText(p3, height=20, wrap="word")
    logbox.pack(fill="both", expand=True)
    lf = ttk.Frame(p3)
    lf.pack(fill="x", pady=(8, 0))
    ttk.Button(lf, text="刷新", command=lambda: fill_log()).pack(side="left", padx=(0, 8))
    ttk.Button(lf, text="打开日志文件",
               command=lambda: os.startfile(LOG_PATH if os.path.exists(LOG_PATH) else BASE_DIR)
               ).pack(side="left")

    def fill_log():
        logbox.delete("1.0", "end")
        logbox.insert("end", "\n".join(LOG.tail(500)))
        logbox.see("end")

    def poll_log():
        lines = LOG.tail(500)
        cur = logbox.get("1.0", "end").count("\n")
        if len(lines) > cur:
            logbox.delete("1.0", "end")
            logbox.insert("end", "\n".join(lines))
            logbox.see("end")
        root.after(1200, poll_log)

    # ---- 自启
    bot = ttk.Frame(root, padding=(12, 0, 12, 12))
    bot.pack(fill="x")

    def toggle_autostart():
        ok, msg = set_autostart(not autostart_enabled())
        autostart_var.set(autostart_enabled())
        status_var.set(msg)
        LOG(msg)

    ttk.Checkbutton(bot, text="开机自启动（启动文件夹）", variable=autostart_var,
                    command=toggle_autostart).pack(side="left")
    ttk.Label(bot, text="pythonw: %s" % os.path.basename(pythonw_path()),
              foreground="#8a929c").pack(side="right")

    fill_log()
    poll_log()
    root.after(600, fill_log)

    if cfg["enabled"] and cfg["username"]:
        start_worker()
        status_var.set("后台已启动")

    if GUI_AUTOCLOSE:
        root.after(2500, root.destroy)

    root.mainloop()


def main():
    global GUI_AUTOCLOSE
    ap = argparse.ArgumentParser(description="NeepuFlow 东电宿舍宽带自动认证")
    ap.add_argument("--daemon", action="store_true", help="后台静默运行")
    ap.add_argument("--selftest", action="store_true", help="自检")
    ap.add_argument("--probe", action="store_true", help="只探测门户")
    ap.add_argument("--login", action="store_true", help="立刻做一次真实认证")
    ap.add_argument("--guitest", action="store_true", help="打开界面后 2.5 秒自动关闭")
    args = ap.parse_args()

    if args.selftest:
        cmd_selftest()
    elif args.probe:
        cmd_probe()
    elif args.login:
        sys.exit(cmd_login())
    elif args.daemon:
        cmd_daemon()
    else:
        if args.guitest:
            GUI_AUTOCLOSE = True
        run_gui()


if __name__ == "__main__":
    main()
