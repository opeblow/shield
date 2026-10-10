"""Real Chromium end-to-end coverage for primary consumer browser flows.

Run with Python Playwright installed and a Shield app at SHIELD_BASE_URL.
This deliberately uses a fresh, disposable account against the test stack.
"""

import json
import os
import uuid
from pathlib import Path

from playwright.sync_api import sync_playwright


BASE = os.environ.get("SHIELD_BASE_URL", "http://127.0.0.1:3001")
REPORT_DIR = Path(os.environ.get("REPORT_DIR", "reports"))
REPORT_DIR.mkdir(parents=True, exist_ok=True)
email = f"browser-{uuid.uuid4().hex[:12]}@example.test"
password = "test-password-123"
results = []
console_errors = []
AXE = Path(os.environ.get("AXE_CORE_PATH", "node_modules/axe-core/axe.min.js"))


def audit_accessibility(name, page):
    if not AXE.exists():
        if os.environ.get("AXE_REQUIRED") == "1":
            raise FileNotFoundError(f"axe-core is required but missing: {AXE}")
        results.append({"name": f"axe: {name}", "status": "UNAVAILABLE", "detail": f"Missing {AXE}"})
        return
    page.add_script_tag(path=str(AXE.resolve()))
    violations = page.evaluate("async () => (await axe.run(document)).violations")
    severe = [item for item in violations if item["impact"] in {"serious", "critical"}]
    detail = json.dumps([{"id": item["id"], "impact": item["impact"], "nodes": len(item["nodes"])} for item in severe])
    check(f"axe: {name}", not severe, detail)


def check(name, condition, detail=""):
    results.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})
    if not condition:
        raise AssertionError(f"{name}: {detail}")


with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True,
        executable_path=os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE") or None,
    )
    context = browser.new_context(viewport={"width": 1440, "height": 1000})
    page = context.new_page()
    page.set_default_timeout(5000)
    page.set_default_navigation_timeout(10000)
    page.on("pageerror", lambda error: console_errors.append(str(error)))

    response = page.goto(BASE, wait_until="domcontentloaded")
    check("landing page loads", response is not None and response.status == 200)
    audit_accessibility("landing desktop", page)
    page.screenshot(path=str(REPORT_DIR / "browser-landing-desktop.png"), full_page=True)

    page.goto(f"{BASE}/auth?mode=signup", wait_until="domcontentloaded")
    audit_accessibility("signup desktop", page)
    page.get_by_label("Email").fill(email)
    page.get_by_label("Password").fill(password)
    page.get_by_role("button", name="Create account").click()
    page.wait_for_url("**/app", timeout=10000)
    check("signup creates session and enters scanner", page.locator("#user-email").inner_text() == email)
    audit_accessibility("scanner desktop", page)

    page.locator("#message").fill("Your bank account is locked. Send your one-time code now to avoid losing access.")
    page.get_by_role("button", name="Check this message").click()
    page.locator("#result:not([hidden])").wait_for(timeout=10000)
    check("scan returns a visible verdict", bool(page.locator("#result h3").inner_text()))
    audit_accessibility("scan result desktop", page)
    page.screenshot(path=str(REPORT_DIR / "browser-scan-desktop.png"), full_page=True)

    page.goto(f"{BASE}/integrations", wait_until="domcontentloaded")
    page.wait_for_timeout(250)
    audit_accessibility("integrations desktop", page)
    check("developer keys page loads for signed-in user", page.get_by_role("heading", name="Developer keys").is_visible())
    page.set_viewport_size({"width": 390, "height": 844})
    audit_accessibility("integrations mobile", page)
    page.set_viewport_size({"width": 1440, "height": 1000})
    page.locator("#signout-btn").click()
    page.wait_for_url(BASE + "/", timeout=10000)
    check("logout returns to landing page", page.url == BASE + "/")
    page.goto(f"{BASE}/app", wait_until="domcontentloaded")
    page.wait_for_url("**/auth", timeout=10000)
    check("guarded scanner redirects after logout", "/auth" in page.url)

    page.set_viewport_size({"width": 1440, "height": 1000})
    for route, label in [("/docs", "docs"), ("/recovery", "recovery"), ("/share", "share")]:
        page.goto(f"{BASE}{route}", wait_until="domcontentloaded")
        audit_accessibility(f"{label} desktop", page)
    page.set_viewport_size({"width": 390, "height": 844})
    for route, label in [("/docs", "docs"), ("/recovery", "recovery"), ("/share", "share")]:
        page.goto(f"{BASE}{route}", wait_until="domcontentloaded")
        audit_accessibility(f"{label} mobile", page)

    page.goto(BASE, wait_until="domcontentloaded")
    audit_accessibility("landing mobile", page)
    page.screenshot(path=str(REPORT_DIR / "browser-landing-mobile.png"), full_page=True)
    overflow = page.evaluate("document.documentElement.scrollWidth > document.documentElement.clientWidth")
    check("mobile landing has no horizontal overflow", not overflow)

    page.goto(f"{BASE}/auth?mode=signup", wait_until="domcontentloaded")
    audit_accessibility("signup mobile", page)
    mobile_email = f"keyboard-{uuid.uuid4().hex[:12]}@example.test"
    for _ in range(5):
        page.keyboard.press("Tab")
    page.keyboard.type(mobile_email)
    page.keyboard.press("Tab")
    page.keyboard.type(password)
    page.keyboard.press("Tab")
    page.keyboard.press("Enter")
    page.wait_for_url("**/app", timeout=10000)
    check("keyboard-only signup completes on mobile", page.locator("#user-email").inner_text() == mobile_email)
    page.locator("#message").fill("Payment alert. Share your OTP now to keep your account.")
    page.get_by_role("button", name="Check this message").click()
    page.locator("#result:not([hidden])").wait_for(timeout=10000)
    audit_accessibility("scanner mobile result", page)

    keyboard_context = browser.new_context(viewport={"width": 390, "height": 844})
    keyboard_page = keyboard_context.new_page()
    keyboard_page.goto(f"{BASE}/auth?mode=signin", wait_until="domcontentloaded")
    keyboard_page.keyboard.press("Tab")
    focused = keyboard_page.evaluate("document.activeElement?.tagName")
    check("keyboard navigation reaches a focusable control", focused in {"A", "BUTTON", "INPUT"}, str(focused))
    check("browser has no uncaught page errors", not console_errors, "; ".join(console_errors))
    keyboard_context.close()
    browser.close()

(REPORT_DIR / "browser-e2e.json").write_text(json.dumps({"base_url": BASE, "results": results}, indent=2))
print(json.dumps({"base_url": BASE, "results": results}, indent=2))
