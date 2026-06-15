"""One-off script to capture dashboard screenshots for README/docs.

Run with the live stack already running on localhost:9090.
"""
from __future__ import annotations

from playwright.sync_api import Page, sync_playwright

URL = "http://localhost:9090/demo/sentinel_war_room_live.html"
OUT = "D:/project/SENTINEL/docs/screenshots"


def shoot(page: Page, selector: str, path: str, retries: int = 5) -> None:
    """Re-locate and screenshot, retrying since the dashboard re-renders live."""
    for attempt in range(retries):
        try:
            locator = page.locator(selector).first
            if locator.count() == 0:
                return
            locator.scroll_into_view_if_needed()
            page.wait_for_timeout(300)
            locator.screenshot(path=path)
            return
        except Exception:
            if attempt == retries - 1:
                raise
            page.wait_for_timeout(500)


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.goto(URL)

        # Let the WebSocket connect and populate live data.
        page.wait_for_timeout(4000)

        # Click through cases until one with completed response actions is shown.
        cases = page.locator("#case-queue .case-card")
        for i in range(min(cases.count(), 10)):
            cases.nth(i).click()
            page.wait_for_timeout(800)
            panel = page.locator(
                "#investigation-body .panel:has(.panel-title:text('Response Actions'))"
            ).first
            if panel.count() > 0 and "Awaiting" not in (panel.inner_text() or ""):
                break

        page.screenshot(path=f"{OUT}/dashboard_overview.png", full_page=False)

        shoot(page, ".kill-chain-container", f"{OUT}/kill_chain.png")
        shoot(page, ".differentiation-panel", f"{OUT}/why_sentinel_wins.png")
        shoot(page, "#agent-list", f"{OUT}/agent_status.png")
        shoot(page, "#metric-grid", f"{OUT}/metrics.png")
        shoot(
            page,
            "#investigation-body .panel:has(.panel-title:text('Response Actions'))",
            f"{OUT}/response_actions.png",
        )

        browser.close()


if __name__ == "__main__":
    main()
