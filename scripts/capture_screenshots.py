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

        # "Response Actions" panel in the center investigation column.
        response_panel = page.locator(
            "#investigation-body .panel:has(.panel-title:text('Response Actions'))"
        ).first
        if response_panel.count() > 0:
            response_panel.scroll_into_view_if_needed()
            page.wait_for_timeout(500)
            response_panel.screenshot(path=f"{OUT}/response_actions.png")

        browser.close()


if __name__ == "__main__":
    main()
