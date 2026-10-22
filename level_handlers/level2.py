# level_handlers/level2.py
import requests
from browser_client import fetch
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog

def run(target: str, mode: str, logger: TextLog, use_browser: bool = False, **kwargs):
    """Level 2 – Low‑risk fuzzing.

    * Sends a POST request with an empty JSON body.
    * Performs a simple *SQL‑error* payload that only triggers error messages
      (no data modification).
    * If `use_browser` is True the request is performed via the Playwright‑based
      `fetch` helper, which mimics a real browser user‑agent.
    """
    logger.write(f"[blue]Level 2 – POST empty + SQL‑error test to {target}[/]")
    test_url = f"{target.rstrip('/')}/login"
    payload = {"username": "'", "password": "'"}  # intentional syntax error

    try:
        if use_browser:
            resp = fetch("POST", test_url, json=payload, timeout=8)
        else:
            resp = requests.post(test_url, json=payload, timeout=8)

        logger.write(f"[green]Status: {resp.status_code}")
        # Detect typical SQL error strings in response body
        error_indicators = ["syntax error", "sql", "database error"]
        found = any(ind in resp.text.lower() for ind in error_indicators)
        if found:
            logger.write("[yellow]Potential SQL‑error indication detected.")
        return {
            "level": 2,
            "target": target,
            "url": test_url,
            "status": resp.status_code,
            "sql_error": found,
        }
    except Exception as e:
        logger.write(f"[red]Error: {e}")
        return {"level": 2, "target": target, "error": str(e)}
