# ██████╗ ██╗   ██╗██████╗  ██████╗ ███████╗████████╗██████╗  █████╗ ███╗   ██╗████████╗███████╗██████╗ 
# ██╔══██╗██║   ██║██╔══██╗██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
# ██████╔╝██║   ██║██║  ██║██║  ███╗█████╗     ██║   ██████╔╝███████║██╔██╗ ██║   ██║   █████╗  ██████╔╝
# ██╔══██╗██║   ██║██║  ██║██║   ██║██╔══╝     ██║   ██╔══██╗██╔══██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
# ██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████╗   ██║   ██████╔╝██║  ██║██║ ╚████║   ██║   ███████╗██║  ██║
# ╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
import argparse
import asyncio
import json
import random
import ssl
import time
import uuid
import base64
import aiohttp
import aiofiles
from aiohttp import ClientSession, TCPConnector
from colorama import Fore, Style, init
from loguru import logger
from websockets_proxy import Proxy, proxy_connect

init(autoreset=True)
CONFIG_FILE = "config.json"
DEVICE_FILE = "devices.json"
PROXY_FILE = "proxy.txt"
PING_INTERVAL = 30
CHECKIN_INTERVAL = 300
DIRECTOR_SERVER = "https://director.getgrass.io"

parser = argparse.ArgumentParser(description="GrassBot")
parser.add_argument("-p", "--proxy-file", help="Path to the proxy file")
args = parser.parse_args()

if args.proxy_file:
    PROXY_FILE = args.proxy_file

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36 OPR/117.0.0.0",
    "Content-Type": "application/json",
    "Accept": "*/*",
    "Origin": "chrome-extension://lkbnfiajjmbhnfledhphioinpickokdi",
    "Accept-Encoding": "gzip, deflate, br, zstd",
    "Connection": "keep-alive"
}

ERROR_PATTERNS = [
    "Host unreachable",
    "[SSL: WRONG_VERSION_NUMBER]",
    "invalid length of packed IP address string",
    "Empty connect reply",
    "Device creation limit exceeded",
    "sent 1011 (internal error) keepalive ping timeout"
]

BANNED_PROXIES = {} 

async def get_ws_endpoints(device_id: str, user_id: str, proxy_url: str):
    url = f"{DIRECTOR_SERVER}/checkin"
    data = {
        "browserId": device_id,
        "userId": user_id,
        "version": "5.1.1",
        "extensionId": "lkbnfiajjmbhnfledhphioinpickokdi",
        "userAgent": HEADERS["User-Agent"],
        "deviceType": "extension"
    }
    connector = TCPConnector(ssl=False)
    async with ClientSession(connector=connector) as session:
        if proxy_url:
            try:
                async with session.post(url, json=data, headers=HEADERS, proxy=proxy_url) as response:
                    if response.status == 201:
                        try:
                            result = await response.json(content_type=None)
                        except Exception as e:
                            logger.error(f"Error decoding JSON: {e}")
                            text = await response.text()
                            result = json.loads(text)
                        destinations = result.get("destinations", [])
                        token = result.get("token", "")
                        destinations = [f"wss://{dest}" for dest in destinations]
                        return destinations, token
                    else:
                        logger.error(f"Failed to check in: Status {response.status}")
                        return [], ""
            except Exception as e:
                logger.error(f"Error during POST request: {e}")
                return [], ""
        else:
            async with session.post(url, json=data, headers=HEADERS) as response:
                if response.status == 201:
                    try:
                        result = await response.json(content_type=None)
                    except Exception as e:
                        logger.error(f"Error decoding JSON: {e}")
                        text = await response.text()
                        result = json.loads(text)
                    destinations = result.get("destinations", [])
                    token = result.get("token", "")
                    destinations = [f"wss://{dest}" for dest in destinations]
                    return destinations, token
                else:
                    logger.error(f"Failed to check in: Status {response.status}")
                    return [], ""

class WebSocketClient:
    def __init__(self, proxy_url: str, device_id: str, user_id: str):
        self.proxy_url = proxy_url
        self.device_id = device_id
        self.user_id = user_id
        self.uri = None

    async def connect(self) -> bool:
        logger.info(f"🖥️ Device ID: {self.device_id}")
        while True:
            try:
                endpoints, token = await get_ws_endpoints(self.device_id, self.user_id, self.proxy_url)
                if not endpoints or not token:
                    logger.error("No valid WebSocket endpoints or token received")
                    return False
                self.uri = f"{endpoints[0]}?token={token}"
                logger.info(f"Connecting to WebSocket URI: {self.uri}")

                await asyncio.sleep(0.1)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE

                async with proxy_connect(
                    self.uri,
                    proxy=Proxy.from_url(self.proxy_url),
                    ssl=ssl_context,
                    extra_headers=HEADERS
                ) as websocket:
                    ping_task = asyncio.create_task(self._send_ping(websocket))
                    checkin_task = asyncio.create_task(self._periodic_checkin())
                    try:
                        await self._handle_messages(websocket)
                    finally:
                        ping_task.cancel()
                        checkin_task.cancel()
                        try:
                            await ping_task
                        except asyncio.CancelledError:
                            pass
                        try:
                            await checkin_task
                        except asyncio.CancelledError:
                            pass
            except Exception as e:
                logger.error(f"🚫 Error with proxy {self.proxy_url}: {str(e)}")
                if any(pattern in str(e) for pattern in ERROR_PATTERNS) or "Rate limited" in str(e):
                    logger.info(f"❌ Banning proxy {self.proxy_url}")
                    BANNED_PROXIES[self.proxy_url] = time.time() + 3600
                    return False
                await asyncio.sleep(5)

    async def _send_ping(self, websocket) -> None:
        while True:
            try:
                message = {
                    "id": str(uuid.uuid4()),
                    "version": "1.0.0",
                    "action": "PING",
                    "data": {}
                }
                await websocket.send(json.dumps(message))
                await asyncio.sleep(PING_INTERVAL)
            except Exception as e:
                logger.error(f"🚫 Error sending ping: {str(e)}")
                break

    async def _periodic_checkin(self) -> None:
        while True:
            await asyncio.sleep(CHECKIN_INTERVAL)
            await get_ws_endpoints(self.device_id, self.user_id, self.proxy_url)

    async def _handle_messages(self, websocket) -> None:
        handlers = {
            "AUTH": self._handle_auth,
            "PONG": self._handle_pong,
            "HTTP_REQUEST": self._handle_http_request
        }
        while True:
            response = await websocket.recv()
            message = json.loads(response)
            logger.info(f"📥 Received message: {message}")
            action = message.get("action")
            handler = handlers.get(action)
            if handler:
                await handler(websocket, message)
            else:
                logger.error(f"No handler for action: {action}")

    async def _handle_auth(self, websocket, message) -> None:
        auth_response = {
            "id": message["id"],
            "origin_action": "AUTH",
            "result": {
                "browser_id": self.device_id,
                "user_id": self.user_id,
                "user_agent": HEADERS["User-Agent"],
                "timestamp": int(time.time()),
                "device_type": "extension",
                "version": "5.1.1",
            }
        }
        await websocket.send(json.dumps(auth_response))

    async def _handle_pong(self, websocket, message) -> None:
        pong_response = {
            "id": message["id"],
            "origin_action": "PONG"
        }
        await websocket.send(json.dumps(pong_response))

    async def _handle_http_request(self, websocket, message) -> None:
        data = message.get("data", {})
        method = data.get("method", "GET").upper()
        url = data.get("url")
        req_headers = data.get("headers", {})
        body = data.get("body")

        try:
            async with aiohttp.ClientSession() as session:
                async with session.request(method, url, headers=req_headers, data=body) as resp:
                    status = resp.status
                    if status == 429:
                        logger.error(f"HTTP_REQUEST returned 429 for proxy {self.proxy_url}")
                        raise Exception("Rate limited")
                    resp_headers = dict(resp.headers)
                    resp_bytes = await resp.read()
        except Exception as e:
            logger.error(f"HTTP_REQUEST error: {e}")
            raise e

        body_b64 = base64.b64encode(resp_bytes).decode()
        result = {
            "url": url,
            "status": status,
            "status_text": "",
            "headers": resp_headers,
            "body": body_b64
        }
        reply = {
            "id": message.get("id"),
            "origin_action": "HTTP_REQUEST",
            "result": result
        }
        await websocket.send(json.dumps(reply))

    async def _remove_proxy_from_list(self) -> None:
        try:
            async with aiofiles.open(PROXY_FILE, "r") as file:
                lines = await file.readlines()
            async with aiofiles.open(PROXY_FILE, "w") as file:
                await file.writelines(line for line in lines if line.strip() != self.proxy_url)
        except Exception as e:
            logger.error(f"🚫 Error removing proxy from file: {str(e)}")

class ProxyManager:
    def __init__(self, device_ids: list, user_id: str):
        self.device_ids = device_ids
        self.user_id = user_id
        self.active_proxies = set()
        self.all_proxies = set()

    async def load_proxies(self) -> None:
        try:
            async with aiofiles.open(PROXY_FILE, "r") as file:
                content = await file.read()
            self.all_proxies = set(line.strip() for line in content.splitlines() if line.strip())
        except Exception as e:
            logger.error(f"❌ Error loading proxies: {str(e)}")

    async def start(self, max_proxies: int) -> None:
        await self.load_proxies()
        if not self.all_proxies:
            logger.error("❌ No proxies found in proxy.txt")
            return
        available_proxies = {p for p in self.all_proxies if p not in BANNED_PROXIES or time.time() >= BANNED_PROXIES[p]}
        if not available_proxies:
            logger.error("❌ No available proxies (all are banned).")
            return
        selected = random.sample(list(available_proxies), min(len(available_proxies), max_proxies))
        self.active_proxies = set(selected)
        tasks = {asyncio.create_task(self._run_client(proxy, device_id)): (proxy, device_id) for proxy, device_id in zip(self.active_proxies, self.device_ids)}

        while True:
            done, pending = await asyncio.wait(tasks.keys(), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                proxy, device_id = tasks.pop(task)
                if task.result() is False:
                    logger.error(f"Proxy {proxy} failed; removing and rotating.")
                    self.active_proxies.remove(proxy)
                    await self.load_proxies()
                    remaining = {p for p in self.all_proxies if p not in self.active_proxies and (p not in BANNED_PROXIES or time.time() >= BANNED_PROXIES[p])}
                    if remaining:
                        new_proxy = random.choice(list(remaining))
                        self.active_proxies.add(new_proxy)
                        new_task = asyncio.create_task(self._run_client(new_proxy, device_id))
                        tasks[new_task] = (new_proxy, device_id)

    async def _run_client(self, proxy: str, device_id: str) -> bool:
        client = WebSocketClient(proxy, device_id, self.user_id)
        return await client.connect()

def setup_logger() -> None:
    logger.remove()
    logger.add("bot.log",
               format=" <level>{level}</level> | <cyan>{message}</cyan>",
               level="INFO", rotation="1 day")
    logger.add(lambda msg: print(msg, end=""),
               format=" <level>{level}</level> | <cyan>{message}</cyan>",
               level="INFO", colorize=True)

async def load_user_config() -> dict:
    try:
        with open(CONFIG_FILE, "r") as config_file:
            config_data = json.load(config_file)
        return config_data if "user_ids" in config_data else {}
    except Exception as e:
        logger.error(f"❌ Error loading configuration: {str(e)}")
        return {}

async def load_device_ids() -> list:
    try:
        with open(DEVICE_FILE, "r") as device_file:
            device_data = json.load(device_file)
        return device_data.get("device_ids", [])
    except Exception as e:
        logger.error(f"❌ Error loading device IDs: {str(e)}")
        return []

async def save_device_ids(device_ids: list) -> None:
    try:
        with open(DEVICE_FILE, "w") as device_file:
            json.dump({"device_ids": device_ids}, device_file, indent=4)
        logger.info(f"✅ Device IDs saved!")
    except Exception as e:
        logger.error(f"❌ Error saving device IDs: {str(e)}")

async def user_input() -> dict:
    user_ids_input = input(f"{Fore.YELLOW}🔑 Enter your USER IDs (comma separated): {Style.RESET_ALL}")
    user_ids = [uid.strip() for uid in user_ids_input.split(",") if uid.strip()]
    config_data = {"user_ids": user_ids}
    with open(CONFIG_FILE, "w") as config_file:
        json.dump(config_data, config_file, indent=4)
    logger.info(f"✅ Configuration saved! USER IDs: {user_ids}")
    return config_data

async def device_input(existing_count: int) -> list:
    if existing_count > 0:
        use_existing = input(f"{Fore.LIGHTYELLOW_EX + Style.BRIGHT}🔑 You have {existing_count} devices already configured. Do you want to use them? (yes/no): {Style.RESET_ALL}").strip().lower()
        if use_existing == "yes":
            return await load_device_ids()

    num_devices_input = input(f"{Fore.LIGHTYELLOW_EX + Style.BRIGHT}🔑 Enter the number of devices you want to create: {Style.RESET_ALL}")
    num_devices = int(num_devices_input)
    device_ids = [str(uuid.uuid4()) for _ in range(num_devices)]
    await save_device_ids(device_ids)
    return device_ids

async def main() -> None:
    print(f"""{Fore.YELLOW + Style.BRIGHT}
██████╗ ██╗   ██╗██████╗  ██████╗ ███████╗████████╗██████╗  █████╗ ███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║   ██║██╔══██╗██╔════╝ ██╔════╝╚══██╔══╝██╔══██╗██╔══██╗████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║   ██║██║  ██║██║  ███╗█████╗     ██║   ██████╔╝███████║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔══██╗██║   ██║██║  ██║██║   ██║██╔══╝     ██║   ██╔══██╗██╔══██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██████╔╝╚██████╔╝██████╔╝╚██████╔╝███████╗   ██║   ██████╔╝██║  ██║██║ ╚████║   ██║   ███████╗██║  ██║
╚═════╝  ╚═════╝ ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
{Style.RESET_ALL}""")
    print(f"{Fore.LIGHTGREEN_EX}GrassBot{Style.RESET_ALL}")
    print(f"{Fore.RED}========================================{Style.RESET_ALL}")
    setup_logger()

    config = await load_user_config()
    if not config or not config.get("user_ids"):
        config = await user_input()

    user_ids = config["user_ids"]

    existing_device_ids = await load_device_ids()
    device_ids = await device_input(len(existing_device_ids))

    max_proxies = len(device_ids)
    for user_id in user_ids:
        logger.info(f"🚀 Starting with USER_ID: {user_id}")
        logger.info(f"📡 Using a maximum of {max_proxies} proxies")
        logger.info(f"⏱️ Ping interval: {PING_INTERVAL} seconds")
        manager = ProxyManager(device_ids, user_id)
        asyncio.create_task(manager.start(max_proxies))

    await asyncio.Event().wait()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n👋 Shutting down gracefully...")
    except Exception as e:
        logger.error(f"❌ Fatal error: {str(e)}")
