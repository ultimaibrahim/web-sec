from playwright.sync_api import sync_playwright
import requests
import random
import time
from typing import Optional, Dict, Any

_use_browser = False
_stealth_mode = False

REAL_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
]

def set_browser_mode(enabled: bool) -> None:
    global _use_browser
    _use_browser = enabled

def set_stealth_mode(enabled: bool) -> None:
    global _stealth_mode
    _stealth_mode = enabled

def is_stealth_enabled() -> bool:
    return _stealth_mode

def get_stealth_headers() -> Dict[str, str]:
    ua = random.choice(REAL_USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "es-ES,es;q=0.9,en-US;q=0.8,en;q=0.7",
        "Accept-Encoding": "gzip, deflate, br",
        "Sec-Ch-Ua": '"Chromium";v="129", "Not=A?Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Linux"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }

class MockResponse:
    def __init__(self, text: str, status_code: int = 200, headers: Optional[Dict[str, str]] = None):
        self.text = text
        self.status_code = status_code
        self.headers = headers or {}

def fetch(*args, **kwargs) -> Any:
    """Helper de peticiones universal compatible con firmas GET y POST/PUT/DELETE.
    Soporta tanto `fetch(url)` como `fetch(method, url, json=..., files=...)`.
    """
    global _use_browser, _stealth_mode

    # Soportar firmas: fetch(url) o fetch(method, url)
    if len(args) == 1:
        method = "GET"
        url = args[0]
    elif len(args) >= 2:
        method = args[0].upper()
        url = args[1]
    else:
        raise ValueError("fetch requiere al menos la URL")

    use_browser = kwargs.pop("use_browser", None)
    if use_browser is None:
        use_browser = _use_browser

    timeout = kwargs.pop("timeout", 10)

    if _stealth_mode:
        jitter = random.uniform(0.8, 2.5)
        time.sleep(jitter)

    headers = get_stealth_headers() if _stealth_mode else {}
    if "headers" in kwargs and kwargs["headers"]:
        headers.update(kwargs.pop("headers"))

    # Peticiones complejas o métodos mutantes vía Requests si Playwright no aplica
    if use_browser and method == "GET" and "files" not in kwargs and "json" not in kwargs:
        with sync_playwright() as p:
            pw_args = []
            if _stealth_mode:
                pw_args = [
                    "--disable-blink-features=AutomationControlled",
                    "--disable-features=IsolateOrigins,site-per-process"
                ]

            browser = p.chromium.launch(headless=True, args=pw_args)
            ua = headers.get("User-Agent") or random.choice(REAL_USER_AGENTS)
            
            # Ejecutar sobre RAM volátil (/dev/shm) para cero persistencia forense en disco
            user_data_shm = "/dev/shm/websec_browser_session"
            context = browser.new_context(
                user_agent=ua,
                viewport={"width": 1920, "height": 1080},
                locale="es-ES",
                timezone_id="UTC"
            )

            if _stealth_mode:
                # Evasión profunda anti-bot: Webdriver, WebGL, Canvas noise y AudioContext
                context.add_init_script("""
                    // 1. Eliminar rastro de automatización
                    Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
                    window.chrome = { runtime: {}, app: {}, loadTimes: () => ({}) };

                    // 2. Mock de plugins y hardware
                    Object.defineProperty(navigator, 'languages', { get: () => ['es-ES', 'es', 'en-US', 'en'] });
                    Object.defineProperty(navigator, 'plugins', { get: () => [1, 2, 3, 4, 5] });
                    Object.defineProperty(navigator, 'hardwareConcurrency', { get: () => 8 });

                    // 3. Canvas Fingerprint Noise sutil
                    const originalToDataURL = HTMLCanvasElement.prototype.toDataURL;
                    HTMLCanvasElement.prototype.toDataURL = function(type) {
                        const ctx = this.getContext('2d');
                        if (ctx) {
                            const imgData = ctx.getImageData(0, 0, Math.min(10, this.width), Math.min(10, this.height));
                            if (imgData && imgData.data.length > 3) {
                                imgData.data[0] = (imgData.data[0] + 1) % 255;
                                ctx.putImageData(imgData, 0, 0);
                            }
                        }
                        return originalToDataURL.apply(this, arguments);
                    };

                    // 4. AudioContext Fingerprint Mitigation
                    if (window.AudioContext || window.webkitAudioContext) {
                        const AudioCtx = window.AudioContext || window.webkitAudioContext;
                        const origGetChannelData = AudioBuffer.prototype.getChannelData;
                        AudioBuffer.prototype.getChannelData = function() {
                            const data = origGetChannelData.apply(this, arguments);
                            for (let i = 0; i < Math.min(10, data.length); i++) {
                                data[i] += 0.0000001;
                            }
                            return data;
                        };
                    }
                """)

            page = context.new_page()
            page.goto(url, timeout=timeout * 1000)
            content = page.content()
            browser.close()
            return MockResponse(content, 200, headers)
    else:
        req_headers = headers if headers else {"User-Agent": "Mozilla/5.0"}
        resp = requests.request(method, url, headers=req_headers, timeout=timeout, **kwargs)
        return resp
