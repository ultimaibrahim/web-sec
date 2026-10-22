# level_handlers/void.py
import requests
from browser_client import fetch
try:
    from textual.widgets import RichLog as TextLog
except ImportError:
    from textual.widgets import TextLog
from credential_scanner import scan_text

def run(target: str, mode: str, logger: TextLog, use_browser: bool = False, **kwargs):
    """void() – Massive destructive actions (opt‑in, triple‑confirm).

    * Bulk POST 200 dummy records.
    * Bulk DELETE all records.
    * Overwrite a static asset via PUT.
    * All network calls can be routed through Playwright (`fetch`) when
      `use_browser` is True, providing realistic headers and sandboxed browsing.
    """
    logger.write(f"[magenta]void() – Starting massive destructive sequence on {target}[/]")
    summary = {}

    # 1️⃣ Bulk create 200 dummy records
    bulk_create_url = f"{target.rstrip('/')}/api/bulk_create"
    bulk_payload = [{"name": f"test_{i}", "value": i} for i in range(200)]
    try:
        if use_browser:
            resp = fetch("POST", bulk_create_url, json=bulk_payload, timeout=15)
        else:
            resp = requests.post(bulk_create_url, json=bulk_payload, timeout=15)
        logger.write(f"[green]Bulk CREATE status: {resp.status_code}")
        summary["bulk_create"] = resp.status_code
    except Exception as exc:
        logger.write(f"[red]Bulk CREATE error: {exc}")
        summary["bulk_create"] = str(exc)

    # 2️⃣ Bulk delete all records
    bulk_delete_url = f"{target.rstrip('/')}/api/bulk_delete"
    try:
        if use_browser:
            resp = fetch("DELETE", bulk_delete_url, timeout=12)
        else:
            resp = requests.delete(bulk_delete_url, timeout=12)
        logger.write(f"[green]Bulk DELETE status: {resp.status_code}")
        summary["bulk_delete"] = resp.status_code
    except Exception as exc:
        logger.write(f"[red]Bulk DELETE error: {exc}")
        summary["bulk_delete"] = str(exc)

    # 3️⃣ Overwrite static asset
    put_url = f"{target.rstrip('/')}/static/logo.png"
    try:
        import base64
        transparent_png = base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/5+BAQAE/AL+XKJ9cQAAAABJRU5ErkJggg=="
        )
        if use_browser:
            resp = fetch(
                "PUT",
                put_url,
                data=transparent_png,
                headers={"Content-Type": "image/png"},
                timeout=10,
            )
        else:
            resp = requests.put(
                put_url,
                data=transparent_png,
                headers={"Content-Type": "image/png"},
                timeout=10,
            )
        logger.write(f"[green]PUT (overwrite) status: {resp.status_code}")
        summary["overwrite_asset"] = resp.status_code
    except Exception as exc:
        logger.write(f"[red]PUT error: {exc}")
        summary["overwrite_asset"] = str(exc)

    # 4️⃣ Scan final GET for leaked credentials
    try:
        if use_browser:
            resp = fetch("GET", target, timeout=8)
        else:
            resp = requests.get(target, timeout=8)
        creds = scan_text(resp.text)
        if creds:
            logger.write(f"[yellow]Credentials discovered after void(): {creds}")
            summary["post_creds"] = creds
    except Exception:
        pass

    return {"level": "void", "target": target, "actions": summary}
