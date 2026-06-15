"""One-off script to capture dashboard screenshots for README/docs.

Run with the live stack already running on localhost:9090.
"""
from __future__ import annotations

import time

from playwright.sync_api import sync_playwright

URL = "http://localhost:9090/demo/sentinel_war_room_live.html"
OUT = "D:/project/SENTINEL/docs/screenshots"


def main() -> None:
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={"width": 1920, "height": 1080})
        page.goto(URL)

        # Let the WebSocket connect and populate live data.
        page.wait_for_timeout(4000)

        # Click the first case in the queue to open the investigation view.
        first_case = page.locator("#case-queue .case-card").first
        if first_case.count() > 0:
            first_case.click()
            page.wait_for_timeout(2000)

        page.screenshot(path=f"{OUT}/dashboard_overview.png", full_page=False)

        # Kill chain lives in the center "Active Investigation" column.
        kill_chain = page.locator(".kill-chain-container").first
        if kill_chain.count() > 0:
            kill_chain.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            kill_chain.screenshot(path=f"{OUT}/kill_chain.png")

        # "Why SENTINEL Wins" differentiation panel in the left column.
        diff_panel = page.locator(".differentiation-panel").first
        if diff_panel.count() > 0:
            diff_panel.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            diff_panel.screenshot(path=f"{OUT}/why_sentinel_wins.png")

        # Agent status cards in the right column.
        agent_list = page.locator("#agent-list").first
        if agent_list.count() > 0:
            agent_list.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            agent_list.screenshot(path=f"{OUT}/agent_status.png")

        # Metrics grid in the right column.
        metrics = page.locator("#metric-grid").first
        if metrics.count() > 0:
            metrics.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            metrics.screenshot(path=f"{OUT}/metrics.png")

        browser.close()


if __name__ == "__main__":
    main()
