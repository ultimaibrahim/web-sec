import requests
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

def run(target: str, mode: str, logger: TextLog, use_browser: bool = False, **kwargs):
    """Level 0 – Passive reconnaissance.

    Performs a HEAD request to fetch headers without a body.
    No side‑effects are caused.
    """
    logger.write(f"[blue]Level 0 – HEAD request to {target}[/]")
    try:
        resp = requests.head(target, timeout=5, allow_redirects=True)
        logger.write(f"[green]Status: {resp.status_code}")
        logger.write(f"[cyan]Headers: {dict(resp.headers)}")
        return {
            "level": 0,
            "target": target,
            "status": resp.status_code,
            "headers": dict(resp.headers),
        }
    except Exception as e:
        logger.write(f"[red]Error: {e}")
        return {"level": 0, "target": target, "error": str(e)}
