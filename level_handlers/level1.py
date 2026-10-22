import requests
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

from browser_client import fetch

def run(target: str, mode: str, logger: TextLog, use_browser: bool = False):
    """Level 1 – Light active checks.

    * GET request with a benign query string.
    * Detects simple reflection of the supplied parameter.
    * Does **not** modify any server state.
    """
    logger.write(f"[blue]Level 1 – GET with benign param to {target}[/]")
    test_url = f"{target.rstrip('/')}/?test=agnostic"
    try:
        if use_browser:
            html = fetch(test_url, use_browser=True)
            # Simple reflection check on raw HTML
            reflected = "agnostic" in html
            logger.write(f"[green]Fetched via browser, reflection: {reflected}")
            status = 200
        else:
            resp = requests.get(test_url, timeout=7)
            logger.write(f"[green]Status: {resp.status_code}")
            reflected = "agnostic" in resp.text
            status = resp.status_code
        if reflected:
            logger.write("[yellow]Potential reflection detected (parameter echoed).")
        return {
            "level": 1,
            "target": target,
            "url": test_url,
            "status": status,
            "reflection": reflected,
        }
    except Exception as e:
        logger.write(f"[red]Error: {e}")
        return {"level": 1, "target": target, "error": str(e)}
    """Level 1 – Light active checks.

    * GET request with a benign query string.
    * Detects simple reflection of the supplied parameter.
    * Does **not** modify any server state.
    """
    logger.write(f"[blue]Level 1 – GET with benign param to {target}[/]")
    test_url = f"{target.rstrip('/')}/?test=agnostic"
    try:
        resp = requests.get(test_url, timeout=7)
        logger.write(f"[green]Status: {resp.status_code}")
        # Simple reflection check
        if "agnostic" in resp.text:
            logger.write("[yellow]Potential reflection detected (parameter echoed).")
        return {
            "level": 1,
            "target": target,
            "url": test_url,
            "status": resp.status_code,
            "reflection": "agnostic" in resp.text,
        }
    except Exception as e:
        logger.write(f"[red]Error: {e}")
        return {"level": 1, "target": target, "error": str(e)}
