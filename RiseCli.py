# This file is part of Rise ToolKit.
# Copyright (c) 2025-Present - Routo

# Rise ToolKit is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# You should have received a copy of the GNU General Public License
# along with Rise ToolKit. If not, see <https://www.gnu.org/licenses/>.




"""guyz we think like things not possible in programming language in which you are working but reality is not this 
yes it also happens with me my previous thinking when i am new in python was like i think how people make these tools and clients
of discord but then when i read discord docs then i know about discord gateway and then i try in python bcz we can also connect 
gateway in python so i try and result you can see ...... 

stay connected with me for more cool stuff"""





import sys
import websocket
import json
import threading
import time
import ssl
import requests
import os
import hashlib
import struct
import socket
import random
import base64
import uuid
import ctypes
import ctypes.util
import array
import zlib
import re

TOKENS_FILE = "tokens.txt"
DATA_FILE = "rise_toolkit_data.json"
CONFIG_FILE = "rise_config.json"

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

try:
    import nacl.secret
    import nacl.utils
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False

class StatusConfig:
    def __init__(self, text="", emoji_name=None, emoji_id=None):
        self.text = text
        self.emoji_name = emoji_name
        self.emoji_id = emoji_id

class ToolkitSettings:
    def __init__(self):
        self.server_id = ""
        self.channel_id = ""
        self.status_configs = []
        self.status_rotation_delay = 10
        self.bio_text = ""


# i try with opus but then i found silent packets . so you don't need dll of opus if you are seeing this code part (opus encoder class)
class OpusEncoder:
    def __init__(self):
        self.sample_rate = 48000
        self.channels = 2
        self.application = 2048
        self.frame_size = 960
        self.bitrate = 64000
        
        opus_path = 'libopus.dll' if os.name == 'nt' else 'libopus.so'
        if not opus_path:
            Logger.log("INFO", "opus dll not found using silent packets")
        
        try:
            self.opus = ctypes.cdll.LoadLibrary(opus_path) if opus_path else None
            self.encoder = None
            if self.opus:
                self._init_encoder()
        except:
            self.opus = None
            self.encoder = None
    
    def _init_encoder(self):
        if not self.opus:
            return
            
        error = ctypes.c_int()
        self.encoder = self.opus.opus_encoder_create(
            ctypes.c_int(self.sample_rate),
            ctypes.c_int(self.channels),
            ctypes.c_int(self.application),
            ctypes.byref(error)
        )
        
        if error.value != 0 or not self.encoder:
            self.encoder = None
            return
        
        self.opus.opus_encoder_ctl(self.encoder, 4002, ctypes.c_int(self.bitrate))
        self.opus.opus_encoder_ctl(self.encoder, 4008, ctypes.c_int(1))
    
    def encode_silence(self):
        if not self.encoder:
            return self._fake_encode()
        
        max_data = 4000
        data = (ctypes.c_char * max_data)()
        
        pcm = array.array('h', [0] * (self.frame_size * self.channels))
        pcm_ptr = (ctypes.c_int16 * len(pcm))(*pcm)
        
        result = self.opus.opus_encode(
            self.encoder,
            ctypes.byref(pcm_ptr),
            ctypes.c_int(self.frame_size),
            data,
            ctypes.c_int(max_data)
        )
        
        if result <= 0:
            return self._fake_encode()
        
        return bytes(data[:result])
    
    def _fake_encode(self):
        return bytes([0xF8, 0xFF, 0xFE] + [0] * 60)
    
    def cleanup(self):
        if self.encoder and self.opus:
            self.opus.opus_encoder_destroy(self.encoder)
            self.encoder = None

class TokenInfo:
    def __init__(self, token, user_id="", username=""):
        self.token = token
        self.user_id = user_id
        self.username = username
        self.guilds = []
        self.voice_channel = None
        self.voice_guild = None
        self.ws = None
        self.voice_ws = None
        self.udp_socket = None
        self.voice_connected = False
        self.udp_connected = False
        self.secret_key = b""
        self.secret_key_bytes = b""
        self.ssrc = 0
        self.sequence = 0
        self.timestamp = 0
        self.session_id = None
        self.endpoint = None
        self.voice_token = None
        self.mute = False
        self.deaf = False
        self.status = "online"
        self.activity = None
        self.last_heartbeat = 0.0
        self.connected = False
        self.latency = 0.0
        self.heartbeat_interval = 0.0
        self.heartbeat_thread = None
        self.voice_heartbeat_thread = None
        self.ws_running = False
        self.voice_ws_running = False
        self.keepalive_thread = None
        self.keepalive_running = False
        self.bio_text = ""
        self.status_configs = []
        self.current_status_index = 0
        self.status_rotation_enabled = False
        self.status_rotation_delay = 10
        self.status_rotation_thread = None
        self.status_rotation_running = False
        self.heartbeat_running = False
        self.session_established = False
        self.retry_count = 0
        self.should_be_connected = False
        self.voice_session_id = None
        self.voice_ws_url = None
        self.voice_heartbeat_interval = 0.0
        self.voice_sequence = 0
        self.voice_ready = False
        self.udp_ip = None
        self.udp_port = 0
        self.external_ip = None
        self.external_port = 0
        self.external_port = 0
        self.encrypt_mode = 'aead_aes256_gcm_rtpsize'
        self.encrypt_box = None
        self.audio_sequence = 0
        self.audio_timestamp = 0
        self.nonce = 0
        self.audio_sending = False
        self.audio_thread = None
        self.audio_running = False
        self.target_voice_channel = None
        self.target_voice_guild = None
        self.auto_rejoin_voice = True
        self.last_voice_ack = 0
        self.reconnect_immediate = False
        self.voice_repair_attempts = 0
        self.voice_check_interval = 30
        self.voice_connection_lock = None
        self.opus_encoder = None
        self.connection_start_time = 0.0
        self.total_reconnects = 0
        self.decompress_obj = None
        self.modes = []
        self.voice_monitor_thread = None
        self.voice_resumable = False
        self.last_voice_seq = -1
        self.super_properties = {}
        self.encoded_super_properties = ""
        self.http_headers = {}
        self.client_build_number = 0
        self.http_headers = {}
        self.client_build_number = 0
        self.browser_version = 0
        self.last_ack = time.time()
        self.last_voice_ack = time.time()
        self.reconnect_lock = threading.Lock()
        self.is_reconnecting = False

class IdentityManager:
    FALLBACK_BUILD_NUMBER = 363459
    FALLBACK_BROWSER_VERSION = 132

    @staticmethod
    def get_build_number():
        try:
            response = requests.get('https://discord.com/login', timeout=5)
            match = re.search(r'assets/(sentry\.\w+)\.js', response.text)
            if match:
                sentry_file = match.group(1)
                response = requests.get(f'https://static.discord.com/assets/{sentry_file}.js', timeout=5)
                build_match = re.search(r'buildNumber\D+(\d+)"', response.text)
                if build_match:
                    return int(build_match.group(1))
        except Exception:
            pass
        return IdentityManager.FALLBACK_BUILD_NUMBER

    @staticmethod
    def get_browser_version():
        try:
            response = requests.get('https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return int(data['versions'][0]['version'].split('.')[0])
        except Exception:
            pass
        return IdentityManager.FALLBACK_BROWSER_VERSION

    @staticmethod
    def get_user_agent(version):
        return f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{version}.0.0.0 Safari/537.36'

    @staticmethod
    def generate_initial_properties():
        build_number = IdentityManager.get_build_number()
        browser_version = IdentityManager.get_browser_version()
        user_agent = IdentityManager.get_user_agent(browser_version)
        
        return build_number, browser_version, user_agent

    @staticmethod
    def generate_identity(build_number, browser_version):
        super_properties = {
            'os': 'Windows',
            'browser': 'Chrome',
            'device': '',
            'system_locale': 'en-US',
            'browser_user_agent': IdentityManager.get_user_agent(browser_version),
            'browser_version': f'{browser_version}.0.0.0',
            'os_version': '10',
            'referrer': '',
            'referring_domain': '',
            'referrer_current': '',
            'referring_domain_current': '',
            'release_channel': 'stable',
            'client_build_number': build_number,
            'client_event_source': None,
            'has_client_mods': False,
            'client_launch_id': str(uuid.uuid4()),
            'client_app_state': 'unfocused',
            'client_heartbeat_session_id': str(uuid.uuid4())
        }
        
        encoded_super_properties = base64.b64encode(json.dumps(super_properties).encode()).decode('utf-8')
        
        headers = {
            'Accept-Language': 'en-US,en;q=0.9',
            'Cache-Control': 'no-cache',
            'Connection': 'keep-alive',
            'Pragma': 'no-cache',
            'Referer': 'https://discord.com/channels/@me',
            'Sec-CH-UA': f'"Not A(Brand";v="8", "Chromium";v="{browser_version}", "Google Chrome";v="{browser_version}"',
            'Sec-CH-UA-Mobile': '?0',
            'Sec-CH-UA-Platform': '"Windows"',
            'Sec-Fetch-Dest': 'empty',
            'Sec-Fetch-Mode': 'cors',
            'Sec-Fetch-Site': 'same-origin',
            'User-Agent': super_properties['browser_user_agent'],
            'X-Super-Properties': encoded_super_properties,
            'X-Debug-Options': 'bugReporterEnabled',
            'X-Discord-Locale': 'en-US',
            'X-Discord-Timezone': 'Asia/Stockholm',
        }
        
        return super_properties, encoded_super_properties, headers

class Logger:
    _lock = threading.Lock()
    _current_prompt = ""
    _is_input_active = False

    @staticmethod
    def set_prompt(prompt, active=True):
        Logger._current_prompt = prompt
        Logger._is_input_active = active

    @staticmethod
    def log(level, message, show_in_terminal=True):
        now = time.localtime()
        time_str = time.strftime("%H:%M:%S", now)
        date_str = time.strftime("%Y-%m-%d (%a)", now)
        
        display_level = {
            "SUCCESS": "DONE",
            "ERROR": "ERROR",
            "WARNING": "SYSTEM",
            "INFO": "LOG",
            "DEBUG": "DEBUG"
        }.get(level, level)
        
        log_message = f"[{time_str}] [{display_level}] {message}"
        file_message = f"[{date_str} {time_str}] [{display_level}] {message}"
        
        try:
            with open("rise_toolkit.log", "a", encoding="utf-8") as f:
                f.write(file_message + "\n")
        except:
            pass

        if show_in_terminal and level != "DEBUG":
            with Logger._lock:
                color = {
                    "SUCCESS": "\033[32m",
                    "ERROR": "\033[31m",
                    "WARNING": "\033[33m",
                    "INFO": "\033[36m"
                }.get(level, "")
                reset = "\033[0m"
                
                if Logger._is_input_active:
                    print(f"\r\033[K{color}{log_message}{reset}")
                    print(f"    {Logger._current_prompt}", end="", flush=True)
                else:
                    print(f"{color}{log_message}{reset}")
    
    @staticmethod
    def voice_log(message):
        Logger.log("INFO", f"Voice: {message}")

class RiseEngine:
    def __init__(self):
        self.tokens = {}
        self.settings = ToolkitSettings()
        
        self.client_build_number, self.browser_version, user_agent = IdentityManager.generate_initial_properties()
        Logger.log("INFO", f"System context active: Build {self.client_build_number}")

        self.ws_headers = {
            "User-Agent": user_agent,
            "Accept-Language": "en-US,en;q=0.9",
            "Content-Type": "application/json",
            "Accept": "*/*",
            "Origin": "https://discord.com",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "Sec-Fetch-Dest": "empty",
            "Referer": "https://discord.com/channels/@me"
        }
        self.WATERMARK_STATUS = StatusConfig(text="Online", emoji_name="⚡")
        self.watchdog_running = True
        self.initialize_application()
    
    def initialize_application(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    for key, value in config.items():
                        setattr(self.settings, key, value)
            
            if os.path.exists(DATA_FILE):
                with open(DATA_FILE, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.settings.server_id = data.get("server_id", "")
                    self.settings.channel_id = data.get("channel_id", "")
                    status_configs = data.get("status_configs", [])
                    self.settings.status_configs = [
                        StatusConfig(
                            text=c.get("text", ""),
                            emoji_name=c.get("emoji_name"),
                            emoji_id=c.get("emoji_id")
                        ) for c in status_configs[:2]
                    ]
                    self.settings.status_rotation_delay = data.get("status_rotation_delay", 10)
                    self.settings.bio_text = data.get("bio_text", "")
            
            self.load_tokens_from_file()
            
            watchdog_thread = threading.Thread(target=self._watchdog_loop, daemon=True, name="Watchdog")
            watchdog_thread.start()
            
            Logger.log("SUCCESS", "Rise Toolkit ecosystem synchronized")
            
        except Exception as e:
            Logger.log("ERROR", f"Initialization failed: {e}")
    
    def _watchdog_loop(self):
        while self.watchdog_running:
            try:
                for token_id, token_data in list(self.tokens.items()):
                    if token_data.should_be_connected:
                        if not token_data.connected and not token_data.ws_running and not token_data.is_reconnecting:
                            Logger.log("WARNING", f"Session restoration active for {token_data.username}")
                            self._reconnect_with_backoff(token_data)
                        
                        elif (token_data.target_voice_channel and 
                              token_data.connected and 
                              token_data.voice_channel != token_data.target_voice_channel):
                            
                            if time.time() - token_data.last_voice_check > 60:
                                Logger.log("WARNING", f"Voice presence restoration triggered for {token_data.username}")
                                self.join_voice_channel(token_data, token_data.target_voice_guild, token_data.target_voice_channel)
                                token_data.last_voice_check = time.time()
                
                time.sleep(30)
            except Exception as e:
                Logger.log("ERROR", f"Watchdog error: {e}")
                time.sleep(30)
    
    def load_tokens_from_file(self):
        try:
            if not os.path.exists(TOKENS_FILE):
                Logger.log("INFO", f"{TOKENS_FILE} not found")
                return
            
            loaded_count = 0
            with open(TOKENS_FILE, 'r', encoding='utf-8') as f:
                for line_num, line in enumerate(f, 1):
                    token = line.strip()
                    if not token or '.' not in token:
                        continue
                    
                    token = token.strip('"\' ')
                    token_id = self.extract_token_id(token)
                    
                    if not self.is_token_valid(token):
                        continue
                    
                    headers = {"Authorization": token, **self.ws_headers}
                    user_data = self.api_request("GET", "https://discord.com/api/v9/users/@me", headers)
                    
                    if not user_data:
                        continue
                    
                    if token in [t.token for t in self.tokens.values()]:
                        continue
                    
                    token_info = TokenInfo(
                        token=token,
                        user_id=user_data['id'],
                        username=f"{user_data['username']}#{user_data.get('discriminator', '0')}"
                    )

                    token_info.client_build_number = self.client_build_number
                    token_info.browser_version = self.browser_version
                    token_info.super_properties, token_info.encoded_super_properties, token_info.http_headers = \
                        IdentityManager.generate_identity(self.client_build_number, self.browser_version)
                    
                    token_info.voice_connection_lock = threading.Lock()
                    token_info.connection_start_time = time.time()
                    
                    self.tokens[token_id] = token_info
                    loaded_count += 1
                    
                    time.sleep(0.5)
            
            if loaded_count:
                Logger.log("SUCCESS", f"Synchronization complete: {loaded_count} accounts found")
                
        except Exception as e:
            Logger.log("ERROR", f"Token loading failed: {e}")
    
    def extract_token_id(self, token: str) -> str:
        try:
            parts = token.split('.')
            if len(parts) >= 3:
                return parts[0]
            return hashlib.md5(token.encode()).hexdigest()[:8]
        except:
            return hashlib.md5(token.encode()).hexdigest()[:8]
    
    def is_token_valid(self, token: str) -> bool:
        return '.' in token and len(token.split('.')) >= 3
    
    def api_request(self, method: str, url: str, headers: dict, json_data=None, timeout=10):
        try:
            response = requests.request(method, url, headers=headers, json=json_data, timeout=timeout)
            if response.status_code == 200:
                return response.json()
            return None
        except Exception:
            return None
    
    def save_application_settings(self):
        try:
            self.save_tokens_to_file()
            
            data = {
                "server_id": self.settings.server_id,
                "channel_id": self.settings.channel_id,
                "status_configs": [
                    {"text": c.text, "emoji_name": c.emoji_name, "emoji_id": c.emoji_id}
                    for c in self.settings.status_configs[:2]
                ],
                "status_rotation_delay": self.settings.status_rotation_delay,
                "bio_text": self.settings.bio_text
            }
            
            with open(DATA_FILE, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return True
        except Exception as e:
            Logger.log("ERROR", f"Settings save failed: {e}")
            return False
    
    def save_tokens_to_file(self):
        try:
            with open(TOKENS_FILE, 'w', encoding='utf-8') as f:
                for token_data in self.tokens.values():
                    f.write(f"{token_data.token}\n")
            return True
        except Exception as e:
            Logger.log("ERROR", f"Token save failed: {e}")
            return False
    
    def add_new_token(self, token: str):
        token = token.strip()
        if not self.is_token_valid(token):
            return False, "Invalid token format"
        
        if token in [t.token for t in self.tokens.values()]:
            return False, "Token already exists"
        
        token_id = self.extract_token_id(token)
        if token_id in self.tokens:
            return False, "Token ID already exists"
        
        headers = {"Authorization": token, **self.ws_headers}
        user_data = self.api_request("GET", "https://discord.com/api/v9/users/@me", headers)
        
        if not user_data:
            return False, "Token validation failed"
        
        token_info = TokenInfo(
            token=token,
            user_id=user_data['id'],
            username=f"{user_data['username']}#{user_data.get('discriminator', '0')}"
        )
        
        token_info.client_build_number = self.client_build_number
        token_info.browser_version = self.browser_version
        token_info.super_properties, token_info.encoded_super_properties, token_info.http_headers = \
            IdentityManager.generate_identity(self.client_build_number, self.browser_version)
        
        token_info.voice_connection_lock = threading.Lock()
        token_info.connection_start_time = time.time()
        
        self.tokens[token_id] = token_info
        self.save_tokens_to_file()
        
        Logger.log("SUCCESS", f"Active: {token_info.username}")
        
        return True, f"Active: {token_info.username}"
    
    def establish_connections(self):
        if not self.tokens:
            Logger.log("INFO", "No tokens to connect")
            return
        
        Logger.log("INFO", f"Synchronizing {len(self.tokens)} account sessions...")
        
        tokens_to_connect = []
        for token_id, token_data in list(self.tokens.items()):
            token_data.should_be_connected = True
            if not token_data.connected:
                if self._initiate_connection(token_data):
                    tokens_to_connect.append(token_data)
                time.sleep(1.5)
        
        if tokens_to_connect:
            start_wait = time.time()
            while time.time() - start_wait < 45:
                pending = [t for t in tokens_to_connect if not t.connected]
                if not pending:
                    break
                
                ready_count = len([t for t in tokens_to_connect if t.connected])
                time.sleep(1)
            
            connected_count = len([t for t in tokens_to_connect if t.connected])
            Logger.log("SUCCESS", f"Sequence complete: {connected_count}/{len(tokens_to_connect)} sessions active")
    
    def _initiate_connection(self, token_data: TokenInfo) -> bool:
        try:
            headers = {"Authorization": token_data.token, **token_data.http_headers}
            
            response = requests.get("https://discord.com/api/v9/gateway", headers=headers, timeout=15)
            
            if response.status_code != 200:
                Logger.log("ERROR", f"Networking fault (Gateway API): {response.status_code}")
                return False
            
            gateway = response.json()
            ws_url = f"{gateway['url']}?v=10&encoding=json&compress=zlib-stream"

            try:
                if hasattr(websocket, "enableTrace"):
                    websocket.enableTrace(False)
            except Exception:
                pass
            
            token_data.ws = websocket.WebSocketApp(
                ws_url,
                on_message=lambda ws, msg: self._handle_ws_message(ws, msg, token_data),
                on_error=lambda ws, err: self._handle_ws_error(ws, err, token_data),
                on_close=lambda ws, code, msg: self._handle_ws_close(ws, code, msg, token_data),
                on_open=lambda ws: self._handle_ws_open(ws, token_data),
                header=headers
            )
            
            token_data.ws_running = True
            token_data.session_established = False
            token_data.decompress_obj = zlib.decompressobj() 
            
            thread = threading.Thread( 
                target=self._websocket_thread, 
                args=(token_data,), 
                daemon=True,
                name=f"WS-{token_data.user_id[:8]}"
            )
            thread.start()
            
            return True
            
        except Exception as e:
            Logger.log("ERROR", f"Initialization sequence failed for {token_data.username}: {e}")
            return False
    
    def _reconnect_with_backoff(self, token_data: TokenInfo, immediate=False):
        if token_data.is_reconnecting:
            return

        with token_data.reconnect_lock:
             if token_data.is_reconnecting:
                 return
             token_data.is_reconnecting = True

        token_data.ws_running = False
        token_data.connected = False
        token_data.decompress_obj = None 
        
        token_data.total_reconnects += 1
        
        if immediate:
            wait_time = 0.05
        elif token_data.total_reconnects > 15:
            wait_time = 300
        elif token_data.total_reconnects > 10:
            wait_time = 120
        elif token_data.total_reconnects > 5:
            wait_time = 60
        else:
            wait_time = min(60, 2 ** min(token_data.retry_count, 6))
            wait_time *= random.uniform(0.8, 1.2)
        
        token_data.retry_count += 1
        
        Logger.log("WARNING", 
            f"Network interruption for {token_data.username}. "
            f"Restoring presence in {wait_time:.2f}s... (Attempt {token_data.retry_count})"
        )
        
        def reconnect_task():
            if wait_time > 0:
                time.sleep(wait_time)
                
            if token_data.should_be_connected:
                if not immediate:
                    time.sleep(random.uniform(0.5, 2.0))
                self._initiate_connection(token_data)
            
            with token_data.reconnect_lock:
                token_data.is_reconnecting = False

        threading.Thread(target=reconnect_task, daemon=True, name=f"Reconnect-{token_data.user_id[:8]}").start()

    def _websocket_thread(self, token_data: TokenInfo):
        try:
            token_data.ws.run_forever(
                sslopt={"cert_reqs": ssl.CERT_NONE}, 
                ping_interval=30, 
                ping_timeout=10
            )
        except Exception as e:
            Logger.log("ERROR", f"WebSocket error: {token_data.username}: {e}")
        finally:
            token_data.ws_running = False
            token_data.connected = False

    def _handle_ws_open(self, ws, token_data: TokenInfo):
        Logger.log("SUCCESS", f"Handshake complete: {token_data.username}")
        token_data.retry_count = 0
        token_data.total_reconnects = 0
        with token_data.reconnect_lock:
            token_data.is_reconnecting = False
        
        if token_data.target_voice_channel and token_data.target_voice_guild:
             pass
    
    def _send_resume(self, token_data: TokenInfo):
        resume = {
            'op': 6,
            'd': {
                'token': token_data.token,
                'session_id': token_data.session_id,
                'seq': token_data.sequence
            }
        }
        Logger.log("INFO", f"Synchronizing existing session state for {token_data.username} (P-ID: {token_data.sequence})")
        self._send_websocket_data(token_data, resume)

    def _send_identify(self, token_data: TokenInfo):
        identify = {
            'op': 2,
            'd': {
                'token': token_data.token,
                'properties': token_data.super_properties, 
                'compress': False,
                'large_threshold': 250,
                'v': 9,
                'presence': {
                    'status': 'online',
                    'since': 0,
                    'activities': [],
                    'afk': False
                }
            }
        }
        self._send_websocket_data(token_data, identify)
    
    def _send_websocket_data(self, token_data: TokenInfo, data: dict) -> bool:
        if not token_data.ws_running or not token_data.ws:
            return False
        
        try:
            token_data.ws.send(json.dumps(data))
            return True
        except Exception as e:
            Logger.log("ERROR", f"Send failed: {token_data.username}: {e}")
            return False
    
    def _handle_ws_message(self, ws, message, token_data: TokenInfo):
        try:
            if isinstance(message, bytes):
                try:
                    if token_data.decompress_obj:
                         message = token_data.decompress_obj.decompress(message).decode('utf-8')
                    else:
                         message = message.decode('utf-8')
                except Exception as e:
                    Logger.log("ERROR", f"Decompression error for {token_data.username}: {e}")
                    token_data.decompress_obj = None 
                    self._reconnect_with_backoff(token_data)
                    return
            
            data = json.loads(message)
            if data.get('s') is not None:
                token_data.sequence = data['s']
            
            if data['op'] == 10:
                token_data.heartbeat_interval = data['d']['heartbeat_interval'] / 1000.0
                
                if token_data.ws_running:
                    self._initiate_heartbeat(token_data)
                    if token_data.session_id and token_data.sequence > 0:
                         self._send_resume(token_data)
                    else:
                         self._send_identify(token_data)
            
            elif data['op'] == 7:
                Logger.log("INFO", f"Upstream networking update scheduled for {token_data.username}")
                token_data.reconnect_immediate = True
                if token_data.ws:
                    token_data.ws.close()
            
            elif data['op'] == 0:
                self._process_dispatch(token_data, data['t'], data['d'])
            
            elif data['op'] == 1:
                self._send_websocket_data(token_data, {"op": 1, "d": token_data.sequence})
            
            elif data['op'] == 11:
                token_data.last_ack = time.time()
                token_data.latency = time.time() - token_data.last_heartbeat
            
            elif data['op'] == 9:
                Logger.log("WARNING", f"Lifecycle refresh required for {token_data.username}. Starting new session.")
                token_data.session_established = False
                token_data.session_id = None
                token_data.sequence = 0

                token_data.reconnect_immediate = True
                if token_data.ws:
                    token_data.ws.close()
                    
        except Exception as e:
            Logger.log("ERROR", f"Message error: {token_data.username}: {e}")
    
    def _initiate_heartbeat(self, token_data: TokenInfo):
        if token_data.heartbeat_thread and token_data.heartbeat_thread.is_alive():
            token_data.heartbeat_running = False
            token_data.heartbeat_thread.join(timeout=1)
        
        token_data.heartbeat_running = True
        
        def heartbeat_task():
            token_data.last_ack = time.time() 
            ack_timeout = 60 
            
            while token_data.ws_running and token_data.heartbeat_running:
                try:
                    if time.time() - token_data.last_ack > ack_timeout:
                        Logger.log("WARNING", f"Heartbeat latency limit exceeded for {token_data.username}. Resetting.")
                        self._reconnect_with_backoff(token_data)
                        break
                    
                    heartbeat = {'op': 1, 'd': token_data.sequence}
                    if self._send_websocket_data(token_data, heartbeat):
                        token_data.last_heartbeat = time.time()
                    else:
                        raise Exception("Failed to send heartbeat")
                    
                    jitter = random.uniform(0.9, 1.1)
                    interval = token_data.heartbeat_interval * jitter
                    time.sleep(interval)
                    
                except Exception:
                    if token_data.should_be_connected:
                        self._reconnect_with_backoff(token_data)
                    break
            
            token_data.heartbeat_running = False
        
        token_data.heartbeat_thread = threading.Thread(
            target=heartbeat_task, 
            args=(), 
            daemon=True,
            name=f"Heartbeat-{token_data.user_id[:8]}"
        )
        token_data.heartbeat_thread.start()
    
    def _process_dispatch(self, token_data: TokenInfo, event: str, data: dict):
        if event == "READY":
            token_data.user_id = data['user']['id']
            token_data.username = f"{data['user']['username']}#{data['user'].get('discriminator', '0')}"
            token_data.session_id = data['session_id']
            token_data.session_established = True
            token_data.retry_count = 0
            
            token_data.voice_resumable = False
            token_data.last_voice_seq = -1
            
            if 'guilds' in data:
                token_data.guilds = [guild['id'] for guild in data['guilds']]
            
            token_data.connected = True
            Logger.log("SUCCESS", f"Session fully active: {token_data.username}")
            
            if token_data.bio_text:
                self.set_user_bio(token_data, token_data.bio_text)
            
            if self.settings.status_configs:
                token_data.status_configs = self.settings.status_configs[:2]
                token_data.status_rotation_delay = self.settings.status_rotation_delay
                
                if token_data.status_rotation_enabled:
                    self.start_status_rotation(token_data, 
                                             token_data.status_configs, 
                                             token_data.status_rotation_delay, 
                                             True)
            
            if token_data.target_voice_channel and token_data.target_voice_guild:
                Logger.log("INFO", f"Restoring voice presence for {token_data.username}...")
                self.join_voice_channel(token_data, token_data.target_voice_guild, token_data.target_voice_channel)
        
        elif event == "RESUMED":
            token_data.connected = True
            token_data.session_established = True
            token_data.total_reconnects = 0
            token_data.retry_count = 0
            Logger.log("SUCCESS", f"Context restored: {token_data.username}")
        
        elif event == "VOICE_STATE_UPDATE":
            if data['user_id'] == token_data.user_id:
                token_data.voice_channel = data.get('channel_id')
                token_data.voice_guild = data.get('guild_id')
                token_data.voice_connected = token_data.voice_channel is not None
                
                Logger.voice_log(f"Voice Update: {token_data.username} -> {token_data.voice_channel}")
                
                if token_data.target_voice_channel and token_data.voice_monitor_thread is None:
                    token_data.voice_monitor_thread = threading.Thread(
                        target=self._voice_monitor_loop,
                        args=(token_data,),
                        daemon=True,
                        name=f"VoiceMonitor-{token_data.user_id[:8]}"
                    )
                    token_data.voice_monitor_thread.start()
        
        elif event == "VOICE_SERVER_UPDATE":
            if data.get('guild_id') == token_data.voice_guild:
                token_data.voice_ws_url = f"wss://{data['endpoint']}?v=8"
                token_data.voice_token = data['token']
                self._establish_voice_connection(token_data)
    
    def _voice_monitor_loop(self, token_data: TokenInfo):
        try:
            while token_data.connected and token_data.auto_rejoin_voice:
                try:
                    should_be_in_voice = token_data.target_voice_channel is not None
                    currently_in_voice = token_data.voice_channel == token_data.target_voice_channel
                    ws_active = token_data.voice_ws_running and token_data.voice_connected
                    
                    if should_be_in_voice and (not currently_in_voice or not ws_active):
                        token_data.voice_repair_attempts += 1
                        Logger.voice_log(f"Voice instability detected for {token_data.username} (In Channel: {currently_in_voice}, WS: {ws_active}, Attempt: {token_data.voice_repair_attempts}). Repairing...")

                        if token_data.voice_repair_attempts > 3:
                            Logger.voice_log(f"Recovery threshold reached for {token_data.username}. Performing hard reset...")
                            self._send_websocket_data(token_data, {
                                'op': 4,
                                'd': {
                                    'guild_id': token_data.voice_guild,
                                    'channel_id': None,
                                    'self_mute': False,
                                    'self_deaf': False
                                }
                            })
                            self._cleanup_voice_connection(token_data)
                            time.sleep(2)
                            token_data.voice_repair_attempts = 0
                        
                        self.join_voice_channel(token_data, token_data.target_voice_guild, token_data.target_voice_channel)
                    else:
                        token_data.voice_repair_attempts = 0
                    
                    for _ in range(token_data.voice_check_interval):
                        if not token_data.connected or not token_data.auto_rejoin_voice:
                            break
                        time.sleep(1)
                        
                except Exception as e:
                    Logger.voice_log(f"Voice monitor error for {token_data.username}: {e}")
                    time.sleep(10)
        finally:
            token_data.voice_monitor_thread = None
    
    def _establish_voice_connection(self, token_data: TokenInfo):
        if not token_data.voice_connection_lock:
            token_data.voice_connection_lock = threading.Lock()
            
        if not token_data.voice_connection_lock.acquire(blocking=False):
            return
        
        try:
            if not token_data.voice_ws_url or not token_data.voice_token or not token_data.session_id:
                return
            
            self._cleanup_voice_connection(token_data)
            
            token_data.voice_ws = websocket.WebSocketApp(
                token_data.voice_ws_url,
                on_message=lambda ws, msg: self._handle_voice_ws_message(ws, msg, token_data),
                on_error=lambda ws, err: self._handle_voice_ws_error(ws, err, token_data),
                on_close=lambda ws, code, msg: self._handle_voice_ws_close(ws, code, msg, token_data),
                on_open=lambda ws: self._handle_voice_ws_open(ws, token_data)
            )
            
            token_data.voice_ws_running = True
            
            thread = threading.Thread(
                target=self._voice_websocket_thread,
                args=(token_data,),
                daemon=True,
                name=f"VoiceWS-{token_data.user_id[:8]}"
            )
            thread.start()
            
        except Exception as e:
            Logger.log("ERROR", f"Failed to establish voice connection for {token_data.username}: {e}")
        finally:
            token_data.voice_connection_lock.release()
    
    def _voice_websocket_thread(self, token_data: TokenInfo):
        try:
            token_data.voice_ws.run_forever(
                sslopt={"cert_reqs": ssl.CERT_NONE}, 
                ping_interval=5, 
                ping_timeout=3
            )
        except Exception as e:
            Logger.voice_log(f"Voice WebSocket error: {token_data.username}: {e}")
        finally:
            token_data.voice_ws_running = False
            self._cleanup_voice_connection(token_data)
    
    def _handle_voice_ws_open(self, ws, token_data: TokenInfo):
        Logger.voice_log(f"Voice WebSocket opened for {token_data.username}")

        if token_data.voice_resumable and token_data.voice_token and token_data.session_id:
             payload = {
                 "op": 7, # resume
                 "d": {
                     "server_id": token_data.voice_guild,
                     "session_id": token_data.session_id,
                     "token": token_data.voice_token,
                     "seq_ack": token_data.last_voice_seq
                 }
             }
             Logger.voice_log(f"Transferring voice session state for {token_data.username} (P-ID: {token_data.last_voice_seq})")
        else:
             token_data.voice_resumable = False
             payload = {
                 "op": 0, # identify
                 "d": {
                     "server_id": token_data.voice_guild,
                     "user_id": token_data.user_id,
                     "session_id": token_data.session_id,
                     "token": token_data.voice_token,
                     "max_dave_protocol_version": 1
                 }
             }
        
        self._send_voice_websocket_data(token_data, payload)
    
    def _handle_voice_ws_message(self, ws, message, token_data: TokenInfo):
        try:
            if isinstance(message, bytes):
                if len(message) >= 3:
                    seq = struct.unpack('>H', message[0:2])[0]
                    op = message[2]
                    token_data.last_voice_seq = seq

                    if op == 6:
                        token_data.last_voice_ack = time.time()
                    return
                return

            data = json.loads(message)

            if 'seq' in data:
                token_data.last_voice_seq = data['seq']
            
            op = data.get('op')
            
            if op == 2:
                token_data.voice_resumable = True
                self._handle_voice_ready(token_data, data['d'])
            elif op == 4:
                self._handle_session_description(token_data, data['d'])
            elif op == 6:
                token_data.last_voice_ack = time.time()
            elif op == 8:
                token_data.voice_heartbeat_interval = data['d']['heartbeat_interval'] / 1000.0
                self._start_voice_heartbeat(token_data)
            elif op == 9:
                token_data.voice_resumable = True
                Logger.voice_log(f"Voice session state recovered for {token_data.username}")
                
        except Exception as e:
            Logger.voice_log(f"Voice message error for {token_data.username}: {e}")
    
    def _handle_voice_ws_error(self, ws, error, token_data: TokenInfo):
        err_msg = str(error)
        Logger.voice_log(f"Voice WebSocket error: {token_data.username}: {err_msg}")
        
        if "4006" in err_msg or "Session is no longer valid" in err_msg:
             token_data.voice_resumable = False
    
    def _handle_voice_ws_close(self, ws, close_status_code, close_msg, token_data: TokenInfo):
        Logger.voice_log(f"Voice WebSocket closed for {token_data.username}: {close_status_code}")
        token_data.voice_ws_running = False
        self._cleanup_voice_connection(token_data)
    
    def _send_voice_websocket_data(self, token_data: TokenInfo, data: dict) -> bool:
        if not token_data.voice_ws_running or not token_data.voice_ws:
            return False
        
        try:
            token_data.voice_ws.send(json.dumps(data))
            return True
        except Exception as e:
            Logger.voice_log(f"Voice send failed: {token_data.username}: {e}")
            return False
    
    def _handle_voice_ready(self, token_data: TokenInfo, data: dict):
        try:
            token_data.ssrc = data['ssrc']
            token_data.udp_ip = data['ip']
            token_data.udp_port = data['port']
            token_data.modes = data['modes']
            Logger.log("INFO", f"Available Voice Modes: {token_data.modes}")
            token_data.voice_ready = True

            if 'aead_aes256_gcm_rtpsize' in token_data.modes and CRYPTO_AVAILABLE:
                token_data.encrypt_mode = 'aead_aes256_gcm_rtpsize'
            elif 'aead_aes256_gcm' in token_data.modes and CRYPTO_AVAILABLE:
                 token_data.encrypt_mode = 'aead_aes256_gcm'
            elif 'xsalsa20_poly1305' in token_data.modes and NACL_AVAILABLE:
                token_data.encrypt_mode = 'xsalsa20_poly1305'
            else:
                Logger.log("WARNING", f"No compatible encryption mode found for {token_data.username}. Defaulting to {token_data.encrypt_mode}")
            
            Logger.voice_log(f"Selected mode for {token_data.username}: {token_data.encrypt_mode}")
            
            self._start_udp_discovery(token_data)
            
        except Exception as e:
            Logger.log("ERROR", f"Voice ready error for {token_data.username}: {e}")
    
    def _handle_session_description(self, token_data: TokenInfo, data: dict):
        Logger.voice_log(f"Session description received for {token_data.username}!")
        
        try:
            if 'secret_key' in data:
                token_data.secret_key = data['secret_key']
                
                if isinstance(token_data.secret_key, list):
                    token_data.secret_key_bytes = bytes(token_data.secret_key)
                else:
                    token_data.secret_key_bytes = base64.b64decode(token_data.secret_key)
                
                Logger.voice_log(f"Secret key received for {token_data.username}: {len(token_data.secret_key_bytes)} bytes")
                
                if len(token_data.secret_key_bytes) != 32:
                    Logger.log("ERROR", f"Invalid secret key length for {token_data.username}: {len(token_data.secret_key_bytes)} bytes, expected 32")
                    self._cleanup_voice_connection(token_data)
                    return
                
                if token_data.encrypt_mode == 'xsalsa20_poly1305' and NACL_AVAILABLE:
                    token_data.encrypt_box = nacl.secret.SecretBox(token_data.secret_key_bytes)
                elif ('aead_aes256_gcm' in token_data.encrypt_mode) and CRYPTO_AVAILABLE:
                     token_data.encrypt_box = AESGCM(token_data.secret_key_bytes)
                
                token_data.voice_connected = True
                token_data.udp_connected = True
                
                Logger.log("SUCCESS", f"Voice synchronization established: {token_data.username}. Secure.")
                self._start_audio_packets(token_data)
                
            else:
                Logger.voice_log(f"No secret key in session description for {token_data.username}")
                
        except Exception as e:
            Logger.log("ERROR", f"Session description error for {token_data.username}: {e}")
    
    def _start_udp_discovery(self, token_data: TokenInfo):
        try:
            token_data.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            token_data.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            token_data.udp_socket.settimeout(5.0)
            
            Logger.voice_log(f"UDP socket created for {token_data.username}: {token_data.udp_ip}:{token_data.udp_port}")
            
            token_data.keepalive_running = True
            token_data.keepalive_thread = threading.Thread(target=self._keepalive_loop, args=(token_data,), daemon=True)
            token_data.keepalive_thread.start()
            
            self._ip_discovery(token_data)
            
        except Exception as e:
            Logger.log("ERROR", f"Transport layer fault for {token_data.username}: {e}")
            self._cleanup_voice_connection(token_data)
    
    def _ip_discovery(self, token_data: TokenInfo):
        try:
            packet = bytearray(74)
            packet[0] = 0x01
            packet[1] = 0x00
            packet[2] = 0x00
            packet[3] = 0x46
            
            struct.pack_into('>I', packet, 4, token_data.ssrc)
            
            token_data.udp_socket.sendto(packet, (token_data.udp_ip, token_data.udp_port))
            Logger.voice_log(f"Initiating network topology discovery for {token_data.username}...")
            
            try:
                response, addr = token_data.udp_socket.recvfrom(74)
                if len(response) >= 74:
                    ip_end = response.find(0, 8)
                    if ip_end > 8:
                        token_data.external_ip = response[8:ip_end].decode('ascii')
                        token_data.external_port = struct.unpack_from('>H', response, 72)[0]
                        
                        Logger.voice_log(f"Discovered IP for {token_data.username}: {token_data.external_ip}:{token_data.external_port}")
                        self._send_udp_connection_info(token_data)
                        return
            except socket.timeout:
                Logger.voice_log(f"Topology discovery timed out for {token_data.username} - switching to relay mode")
            
            token_data.external_ip = token_data.udp_ip
            token_data.external_port = token_data.udp_port
            Logger.voice_log(f"Using server IP for {token_data.username}: {token_data.external_ip}:{token_data.external_port}")
            self._send_udp_connection_info(token_data)
                
        except Exception as e:
            Logger.voice_log(f"IP discovery error for {token_data.username}: {e}")
            token_data.external_ip = token_data.udp_ip
            token_data.external_port = token_data.udp_port
            Logger.voice_log(f"Internal relay active for {token_data.username}: {token_data.external_ip}")
            self._send_udp_connection_info(token_data)
    
    def _send_udp_connection_info(self, token_data: TokenInfo):
        try:
            time.sleep(1)
            self._send_select_protocol(token_data)
            Logger.voice_log(f"Awaiting link authorization for {token_data.username}...")
        except Exception as e:
            Logger.log("ERROR", f"UDP connection info error for {token_data.username}: {e}")
    
    def _send_select_protocol(self, token_data: TokenInfo):
        try:
            select_protocol = {
                'op': 1,
                'd': {
                    'protocol': 'udp',
                    'data': {
                        'address': token_data.external_ip,
                        'port': token_data.external_port,
                        'mode': token_data.encrypt_mode
                    }
                }
            }
            self._send_voice_websocket_data(token_data, select_protocol)
            Logger.voice_log(f"Protocol handshake synchronized for {token_data.username}")
        except Exception as e:
            Logger.log("ERROR", f"Protocol selection error for {token_data.username}: {e}")
    
    def _start_voice_heartbeat(self, token_data: TokenInfo):
        if token_data.voice_heartbeat_thread and token_data.voice_heartbeat_thread.is_alive():
            token_data.voice_heartbeat_running = False
            token_data.voice_heartbeat_thread.join(timeout=1)
        
        token_data.voice_heartbeat_running = True
        
        def voice_heartbeat_task():
            while token_data.voice_ws_running and token_data.voice_heartbeat_running:
                try:
                    heartbeat = {
                        "op": 3, 
                        "d": {
                            "t": int(time.time() * 1000),
                            "seq_ack": token_data.last_voice_seq
                        }
                    }
                    if self._send_voice_websocket_data(token_data, heartbeat):
                        pass
                    else:
                        raise Exception("Failed to send voice heartbeat")
                    time.sleep(token_data.voice_heartbeat_interval)
                except Exception:
                    self._cleanup_voice_connection(token_data)
                    break
        
        token_data.voice_heartbeat_thread = threading.Thread(
            target=voice_heartbeat_task,
            args=(),
            daemon=True,
            name=f"VoiceHB-{token_data.user_id[:8]}"
        )
        token_data.voice_heartbeat_thread.start()
    
    def _start_audio_packets(self, token_data: TokenInfo):
        if not token_data.opus_encoder:
            token_data.opus_encoder = OpusEncoder()
        
        if token_data.audio_thread and token_data.audio_thread.is_alive():
            token_data.audio_running = False
            token_data.audio_thread.join(timeout=1)
        
        token_data.audio_running = True
        
        def audio_task():
            while token_data.audio_running and token_data.udp_connected:
                try:
                    encoded_audio = token_data.opus_encoder.encode_silence()
                    
                    header = bytearray(12)
                    header[0] = 0x80
                    header[1] = 0x78
                    struct.pack_into('>H', header, 2, token_data.audio_sequence)
                    struct.pack_into('>I', header, 4, token_data.audio_timestamp)
                    struct.pack_into('>I', header, 8, token_data.ssrc)
                    
                    token_data.audio_sequence = (token_data.audio_sequence + 1) % 65536
                    token_data.audio_timestamp = (token_data.audio_timestamp + 960) % 4294967296
                    
                    if ('aead_aes256_gcm' in token_data.encrypt_mode) and CRYPTO_AVAILABLE:
                         
                         nonce_int = token_data.nonce
                         nonce_bytes_4 = struct.pack('>I', nonce_int) # 4 bytes
                         # you can also take this information from docs if you are developer(read comments in starting of code)
                         # discord requires a 12-byte nonce for the GCM encryption:
                         # the 4 bytes from the counter, padded with 8 null bytes.
                         nonce_gcm = nonce_bytes_4 + b'\x00\x00\x00\x00\x00\x00\x00\x00' 
                         
                         encrypted_data = token_data.encrypt_box.encrypt(nonce_gcm, encoded_audio, None)
                         
                         # append the 4-byte nonce to the end of the packet as required by 'aead_aes256_gcm'
                         final_packet = header + encrypted_data + nonce_bytes_4
                         
                    elif token_data.encrypt_mode == 'xsalsa20_poly1305' and token_data.encrypt_box and NACL_AVAILABLE:
                        nonce_bytes = struct.pack('<I', token_data.nonce)[:12] + bytes(12)
                        encrypted = token_data.encrypt_box.encrypt(encoded_audio, nonce_bytes)
                        final_packet = header + encrypted.ciphertext
                    else:
                        final_packet = header + encoded_audio
                    
                    token_data.nonce = (token_data.nonce + 1) & 0xFFFFFFFF
                    token_data.udp_socket.sendto(final_packet, (token_data.udp_ip, token_data.udp_port))
                    
                    time.sleep(0.02)
                    
                except Exception as e:
                    Logger.voice_log(f"Audio packet error for {token_data.username}: {e}")
                    time.sleep(0.1)
            
            token_data.audio_running = False
        
        token_data.audio_thread = threading.Thread(
            target=audio_task,
            args=(),
            daemon=True,
            name=f"Audio-{token_data.user_id[:8]}"
        )
        token_data.audio_thread.start()
    
    def _keepalive_loop(self, token_data: TokenInfo):
        while token_data.keepalive_running:
            try:
                if token_data.udp_connected:
                    keepalive_packet = b'\x00\x00\x00\x00\x00\x00\x00\x00'
                    token_data.udp_socket.sendto(keepalive_packet, (token_data.udp_ip, token_data.udp_port))
                time.sleep(5)
            except:
                break
    
    def _cleanup_voice_connection(self, token_data: TokenInfo):
        try:
            current = threading.current_thread()
            token_data.audio_running = False
            if token_data.audio_thread and token_data.audio_thread.is_alive():
                if token_data.audio_thread != current:
                    token_data.audio_thread.join(timeout=1)
            
            token_data.voice_heartbeat_running = False
            if token_data.voice_heartbeat_thread and token_data.voice_heartbeat_thread.is_alive():
                if token_data.voice_heartbeat_thread != current:
                    token_data.voice_heartbeat_thread.join(timeout=1)
            
            if token_data.opus_encoder:
                token_data.opus_encoder.cleanup()
                token_data.opus_encoder = None
            
            token_data.keepalive_running = False
            if token_data.keepalive_thread and token_data.keepalive_thread.is_alive():
                if token_data.keepalive_thread != current:
                    token_data.keepalive_thread.join(timeout=1)
            
            if token_data.udp_socket:
                token_data.udp_socket.close()
                token_data.udp_socket = None
            
            token_data.voice_ws_running = False
            if token_data.voice_ws:
                try:
                    token_data.voice_ws.close()
                except:
                    pass
                token_data.voice_ws = None
            
            token_data.voice_ready = False
            token_data.udp_connected = False
            token_data.audio_sending = False
            
        except Exception as e:
            Logger.voice_log(f"Voice cleanup sequence fault: {e}")

    def _handle_ws_error(self, ws, error, token_data: TokenInfo):
        error_str = str(error)     
        if "opcode=8" in error_str or "client reconnect" in error_str:
            Logger.log("INFO", f"Seamless networking transition active for {token_data.username}")
            return

        Logger.log("ERROR", f"WebSocket error: {token_data.username}: {error_str}")
        self._reconnect_with_backoff(token_data)

    def _handle_voice_ws_close(self, ws, code, msg, token_data: TokenInfo):
        token_data.voice_connected = False
        token_data.voice_ws_running = False
        
        if code == 4006:
            Logger.voice_log(f"Voice session invalid (4006) for {token_data.username}. Resetting.")
            token_data.voice_resumable = False
            token_data.last_voice_seq = -1
            
        Logger.voice_log(f"Voice WebSocket closed for {token_data.username}: {code} {msg}")
    
    def _handle_ws_close(self, ws, code, msg, token_data: TokenInfo):
        token_data.connected = False
        token_data.ws_running = False
        if token_data.reconnect_immediate:
            token_data.reconnect_immediate = False
            self._reconnect_with_backoff(token_data, immediate=True)
            return

        token_data.session_established = False
        
        if hasattr(token_data, 'heartbeat_running'):
            token_data.heartbeat_running = False
        
        if code in [4004, 4010, 4011, 4012, 4013, 4014]:
            Logger.log("ERROR", f"Authentication failure ({code}) for {token_data.username}. Termination required.")
            token_data.should_be_connected = False
            return
        
        if token_data.should_be_connected:
            Logger.log("WARNING", f"WS Close {code}: {token_data.username}. Reconnecting...")
            self._reconnect_with_backoff(token_data)

    def join_voice_channel(self, token_data: TokenInfo, guild_id: str, channel_id: str) -> bool:
        if not token_data.connected:
            return False
        
        token_data.target_voice_guild = guild_id
        token_data.target_voice_channel = channel_id
        token_data.last_voice_check = time.time()
        
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': guild_id,
                'channel_id': channel_id,
                'self_mute': token_data.mute,
                'self_deaf': token_data.deaf,
                'self_video': False
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def leave_voice_channel(self, token_data: TokenInfo) -> bool:
        if not token_data.voice_guild:
            return False
        
        token_data.target_voice_guild = None
        token_data.target_voice_channel = None
        
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': token_data.voice_guild,
                'channel_id': None,
                'self_mute': False,
                'self_deaf': False
            }
        }
        
        self._cleanup_voice_connection(token_data)
        
        return self._send_websocket_data(token_data, voice_state)
    
    def toggle_mute_state(self, token_data: TokenInfo) -> bool:
        if not token_data.voice_guild:
            return False
        
        token_data.mute = not token_data.mute
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': token_data.voice_guild,
                'channel_id': token_data.voice_channel,
                'self_mute': token_data.mute,
                'self_deaf': token_data.deaf
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def toggle_deafen_state(self, token_data: TokenInfo) -> bool:
        if not token_data.voice_guild:
            return False
        
        token_data.deaf = not token_data.deaf
        voice_state = {
            'op': 4,
            'd': {
                'guild_id': token_data.voice_guild,
                'channel_id': token_data.voice_channel,
                'self_mute': token_data.mute,
                'self_deaf': token_data.deaf
            }
        }
        
        return self._send_websocket_data(token_data, voice_state)
    
    def set_user_status(self, token_data: TokenInfo, status: str) -> bool:
        if not token_data.connected:
            return False
        
        payload = {
            "op": 3,
            "d": {
                "since": 0,
                "activities": [],
                "status": status,
                "afk": False
            }
        }
        
        if self._send_websocket_data(token_data, payload):
            token_data.status = status
            return True
        return False
    
    def set_user_bio(self, token_data: TokenInfo, bio: str) -> bool:
        try:
            clean_bio = bio.strip()[:190]
            
            headers = {"Authorization": token_data.token, **self.ws_headers}
            
            endpoints = ["https://discord.com/api/v9/users/@me", "https://discord.com/api/v9/users/@me/profile"]
            
            for endpoint in endpoints:
                try:
                    response = requests.patch(endpoint, headers=headers, json={"bio": clean_bio}, timeout=10)
                    if response.status_code in [200, 201, 204]:
                        token_data.bio_text = clean_bio
                        self.settings.bio_text = clean_bio
                        self.save_application_settings()
                        return True
                except Exception:
                    continue
            
            return False
        except Exception as e:
            Logger.log("ERROR", f"Bio error: {token_data.username}: {e}")
            return False
    
    def set_custom_user_status(self, token_data: TokenInfo, text: str, emoji_name: str = None, emoji_id: str = None) -> bool:
        if not token_data.connected:
            return False
        
        emoji = None
        if emoji_name:
            emoji = {"name": emoji_name}
            if emoji_id:
                emoji["id"] = emoji_id
        
        activity = {
            "name": "Custom Status",
            "type": 4,
            "state": text,
        }
        
        if emoji:
            activity["emoji"] = emoji
        
        payload = {
            "op": 3,
            "d": {
                "since": 0,
                "activities": [activity] if text or emoji else [],
                "status": token_data.status,
                "afk": False
            }
        }
        
        return self._send_websocket_data(token_data, payload)
    
    def start_status_rotation(self, token_data: TokenInfo, configs, delay: int = 10, enabled: bool = True):
        if not configs:
            return
        
        token_data.status_configs = configs[:2]
        token_data.status_rotation_delay = delay
        token_data.current_status_index = 0
        
        self.settings.status_configs = configs[:2]
        self.settings.status_rotation_delay = delay
        self.save_application_settings()
        
        if enabled:
            token_data.status_rotation_enabled = True
            if token_data.status_rotation_running:
                token_data.status_rotation_running = False
                if token_data.status_rotation_thread:
                    token_data.status_rotation_thread.join(timeout=1)
            
            token_data.status_rotation_running = True
            token_data.status_rotation_thread = threading.Thread(
                target=self._status_rotation_process,
                args=(token_data,),
                daemon=True,
                name=f"StatusRot-{token_data.user_id[:8]}"
            )
            token_data.status_rotation_thread.start()
        else:
            token_data.status_rotation_enabled = False
            token_data.status_rotation_running = False
    
    def _status_rotation_process(self, token_data: TokenInfo):
        while (token_data.status_rotation_running and 
               token_data.status_rotation_enabled and 
               token_data.connected):
            try:
                all_statuses = token_data.status_configs[:2] + [self.WATERMARK_STATUS]
                
                if not all_statuses:
                    break
                
                current_index = token_data.current_status_index % len(all_statuses)
                current_status = all_statuses[current_index]
                
                self.set_custom_user_status(
                    token_data, 
                    current_status.text, 
                    current_status.emoji_name, 
                    current_status.emoji_id
                )
                
                token_data.current_status_index += 1
                
                for _ in range(token_data.status_rotation_delay):
                    if not (token_data.status_rotation_running and 
                           token_data.status_rotation_enabled and 
                           token_data.connected):
                        break
                    time.sleep(1)
                    
            except Exception as e:
                break
    
    def bulk_operation(self, operation: str, *args):
        success_count = 0
        
        for token_data in self.tokens.values():
            try:
                result = False
                if operation == "join_voice" and len(args) >= 2:
                    result = self.join_voice_channel(token_data, args[0], args[1])
                elif operation == "leave_voice":
                    result = self.leave_voice_channel(token_data)
                elif operation == "toggle_mute":
                    result = self.toggle_mute_state(token_data)
                elif operation == "toggle_deafen":
                    result = self.toggle_deafen_state(token_data)
                elif operation == "set_status" and args:
                    result = self.set_user_status(token_data, args[0])
                elif operation == "set_bio" and args:
                    result = self.set_user_bio(token_data, args[0])
                elif operation == "set_custom_status" and args:
                    if len(args) == 1:
                        result = self.set_custom_user_status(token_data, args[0])
                    elif len(args) == 3:
                        result = self.set_custom_user_status(token_data, args[0], args[1], args[2])
                elif operation == "set_status_rotation" and args:
                    if len(args) >= 2:
                        self.start_status_rotation(token_data, args[0], args[1], args[2] if len(args) > 2 else True)
                        result = True
                
                if result:
                    success_count += 1
                
                time.sleep(0.1)
                
            except Exception as e:
                Logger.log("ERROR", f"Bulk error: {token_data.username}: {e}")
        
        return success_count

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def get_input(prompt: str, default: str = "") -> str:
    prompt_text = f"{prompt} [{default}]: " if default else f"{prompt}: "
    Logger.set_prompt(prompt_text, True)
    user_input = input("").strip()
    Logger.set_prompt("", False)
    
    if user_input == "." and default:
        return default
        
    if not user_input and default:
        return default
        
    return user_input

def get_input_id(prompt: str, default: str = "") -> str:
    while True:
        val = get_input(prompt, default)
        if not val: 
             return "" 
        
        if val.isdigit():
            return val
            
        print("    \033[31mInvalid ID. Must be numeric. try again.\033[0m")

def print_banner():
    banner = """\033[36m
__________.___  ____________________       ____  __.______________
\______   \   |/   _____/\_   _____/      |    |/ _|   \__    ___/
 |       _/   |\_____  \  |    __)_       |      < |   | |    |   
 |    |   \   |/        \ |        \      |    |  \|   | |    |   
 |____|_  /___/_______  //_______  /      |____|__ \___| |____|   
        \/            \/         \/               \/                
    \033[0m"""
    print(banner)
    print("\033[1;30m    Rise Toolkit CLI Edition - Dev by Routo\033[0m")
    print("\033[1;30m    -----------------------------------------\033[0m")

def main_menu():
    engine = RiseEngine()
    
    while True:
        try:
            time.sleep(1)
            clear_screen()
            print_banner()
            
            connected_count = sum(1 for t in engine.tokens.values() if t.connected)
            voice_connected_count = sum(1 for t in engine.tokens.values() if t.voice_connected)
            print(f"\n    \033[36mTokens Loaded: {len(engine.tokens)} | Connected: {connected_count} | In Voice: {voice_connected_count}\033[0m\n")
            
            print("    [1>] Load Tokens from File")
            print("    [2>] Add New Token")
            print("    [3>] Connect All Tokens")
            print("    [4>] Disconnect All")
            print("    [5>] Voice Manager (Join/Leave/Mute)")
            print("    [6>] Status Manager (Rotation/Online/Idle)")
            print("    [7>] Set Bio (All Tokens)")
            print("    [8>] List All Tokens")
            print("    [9>] Exit")
            
            prompt = "\033[33m>> Select Option: \033[0m"
            Logger.set_prompt(prompt, True)
            choice = input("").strip()
            Logger.set_prompt("", False)
            
            if choice == "1":
                engine.load_tokens_from_file()
                input("\n[+ routo]     Press Enter (or type anything) to continue...")
            
            elif choice == "2":
                token = input("\n    Enter Discord Token: ").strip()
                if token:
                    success, msg = engine.add_new_token(token)
                    print(f"    {msg}")
                else:
                    print("    Invalid input.")
                input("\n    Press Enter (or type anything) to continue...")
            
            elif choice == "3":
                engine.establish_connections()
                input("\n    Press Enter (or type anything) to continue...")
            
            elif choice == "4":
                count = 0
                for token_data in engine.tokens.values():
                    token_data.should_be_connected = False
                    if token_data.ws:
                        token_data.ws.close()
                        count += 1
                Logger.log("INFO", f"Downtime synchronized: {count} accounts offline.")
                input("\n    Press Enter (or type anything) to continue...")
            
            elif choice == "5":
                while True:
                    clear_screen()
                    print_banner()
                    print("\n    --- Voice Manager ---")
                    print("    [1] Join Channel")
                    print("    [2] Leave Channel")
                    print("    [3] Toggle Mute")
                    print("    [4] Toggle Deafen")
                    print("    [0] Back to Main Menu")
                    v_choice = input("\n    >> Select: ")
                    
                    if v_choice == "0":
                        break
                    
                    if v_choice == "1":
                        sid = get_input_id("    Server ID", engine.settings.server_id)
                        cid = get_input_id("    Channel ID", engine.settings.channel_id)
                        
                        if sid and cid:
                            engine.settings.server_id = sid
                            engine.settings.channel_id = cid
                            engine.save_application_settings()
                            c = engine.bulk_operation("join_voice", sid, cid)
                            print(f"    Instruction broadcast to {c} accounts.")
                             
                            print("    Synchronizing presence...", end="", flush=True)
                            start_wait = time.time()
                            while time.time() - start_wait < 15:
                                connected_count = sum(1 for t in engine.tokens.values() if t.voice_connected and t.udp_connected)
                                if connected_count >= c:
                                    break
                                time.sleep(0.5)
                                print(".", end="", flush=True)
                            print()
                            
                            voice_count = sum(1 for t in engine.tokens.values() if t.voice_connected)
                            print(f"    \033[32mActive presence established: {voice_count}/{len(engine.tokens)}\033[0m")
                    elif v_choice == "2":
                        c = engine.bulk_operation("leave_voice")
                        print(f"    Operation sent to {c} tokens.")
                    elif v_choice == "3":
                        c = engine.bulk_operation("toggle_mute")
                        print(f"    Operation sent to {c} tokens.")
                    elif v_choice == "4":
                        c = engine.bulk_operation("toggle_deafen")
                        print(f"    Operation sent to {c} tokens.")
                    
                    time.sleep(1) 
                    input("\n    Press Enter (or type anything) to continue...")
            
            elif choice == "6":
                while True:
                    clear_screen()
                    print_banner()
                    print("\n    --- Status Manager ---")
                    print("    [1] Set Status (Online/Idle/DMD/Invisible)")
                    print("    [2] Start Custom Rotation")
                    print("    [3] Stop Rotation")
                    print("    [0] Back to Main Menu")
                    s_choice = input("\n    >> Select: ")
                    
                    if s_choice == "0":
                        break
                    
                    if s_choice == "1":
                        status = input("    Status (online/idle/dnd/invisible): ").strip().lower()
                        if status in ["online", "idle", "dnd", "invisible"]:
                            engine.bulk_operation("set_status", status)
                        else:
                            print("    Invalid status.")
                    elif s_choice == "2":
                        def_t1, def_e1 = "", ""
                        def_t2, def_e2 = "", ""
                        if len(engine.settings.status_configs) > 0:
                            def_t1 = engine.settings.status_configs[0].text
                            def_e1 = engine.settings.status_configs[0].emoji_name or ""
                        if len(engine.settings.status_configs) > 1:
                            def_t2 = engine.settings.status_configs[1].text
                            def_e2 = engine.settings.status_configs[1].emoji_name or ""
                        
                        text1 = get_input("    Status 1 Text", def_t1)
                        emoji1 = get_input("    Status 1 Emoji (optional)", def_e1)
                        text2 = get_input("    Status 2 Text", def_t2)
                        emoji2 = get_input("    Status 2 Emoji (optional)", def_e2)
                        delay = get_input("    Rotation Delay (sec)", str(engine.settings.status_rotation_delay))
                        
                        try:
                            delay = int(delay)
                        except:
                            delay = 10
                        
                        configs = []
                        if text1: configs.append(StatusConfig(text=text1, emoji_name=emoji1 or None))
                        if text2: configs.append(StatusConfig(text=text2, emoji_name=emoji2 or None))
                        
                        if configs:
                            engine.bulk_operation("set_status_rotation", configs, delay, True)
                        else:
                            print("    No statuses provided.")
                    elif s_choice == "3":
                        for t in engine.tokens.values():
                            t.status_rotation_enabled = False
                        print("    Rotation stopped.")
                    
                    time.sleep(1)
                    input("\n [+ routo]   Press Enter (or type anything) to continue...")
            
            elif choice == "7":
                bio = get_input("    Update Profile Bio", engine.settings.bio_text)
                c = engine.bulk_operation("set_bio", bio)
                print(f"    Metadata synchronized for {c} accounts.")
                time.sleep(1)
                input("\n    Press Enter (or type anything) to continue...")
            
            elif choice == "8":
                print("\n    --- Token List ---")
                for i, (tid, t) in enumerate(engine.tokens.items(), 1):
                    retry_info = f" | Retries: {t.retry_count}" if t.retry_count > 0 else ""
                    voice_info = f" | Voice: {'Connected' if t.voice_connected else 'Disconnected'}"
                    status = "Connected" if t.connected else "Offline"
                    print(f"    {i}. {t.username} [{status}{retry_info}{voice_info}]")
                input("\n    Press Enter (or type anything) to continue...")
            
            elif choice == "9":
                sys.exit()
                
        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            Logger.log("ERROR", f"Menu Error: {e}")
            input("Press Enter...")

if __name__ == "__main__":
    try:
        if os.name == 'nt':
            os.system('cls')
        main_menu()
    except Exception as e:
        print(f"Fatal Error: {e}")
        input()


