#!/usr/bin/env python3
"""Capture Splunkbase screenshots from a running Splunk instance with Playwright."""

import time
from playwright.sync_api import sync_playwright

SPLUNK_URL = "http://localhost:18000"
USERNAME = "admin"
PASSWORD = "TestPassword123!"
OUTPUT_DIR = "screenshots"


def main():
    import os

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            viewport={"width": 1920, "height": 1080},
            ignore_https_errors=True,
        )
        page = context.new_page()

        # Login
        print("Logging in...")
        page.goto(f"{SPLUNK_URL}/en-US/account/login")
        page.wait_for_load_state("networkidle")
        page.fill('input[name="username"]', USERNAME)
        page.fill('input[name="password"]', PASSWORD)
        page.click('button[type="submit"], input[type="submit"]')
        page.wait_for_load_state("networkidle")
        time.sleep(3)

        # Dismiss any modals/tours
        try:
            page.click('button:has-text("Skip")', timeout=3000)
        except Exception:
            pass
        try:
            page.click('button:has-text("Got it")', timeout=2000)
        except Exception:
            pass
        try:
            page.click('button:has-text("Close")', timeout=2000)
        except Exception:
            pass

        # EPSS Overview dashboard
        print("Capturing EPSS Overview dashboard...")
        page.goto(f"{SPLUNK_URL}/en-US/app/TA-epss/epss_overview")
        page.wait_for_load_state("networkidle")
        time.sleep(15)  # Wait for dashboard panels to render
        try:
            page.click('button:has-text("Skip")', timeout=2000)
        except Exception:
            pass
        try:
            page.click('button:has-text("Got it")', timeout=2000)
        except Exception:
            pass
        page.screenshot(path=f"{OUTPUT_DIR}/epss_overview.png", full_page=True)
        print(f"  Saved {OUTPUT_DIR}/epss_overview.png")

        # EPSS Health dashboard
        print("Capturing EPSS Health dashboard...")
        page.goto(f"{SPLUNK_URL}/en-US/app/TA-epss/epss_health")
        page.wait_for_load_state("networkidle")
        time.sleep(15)
        page.screenshot(path=f"{OUTPUT_DIR}/epss_health.png", full_page=True)
        print(f"  Saved {OUTPUT_DIR}/epss_health.png")

        # Search results showing raw EPSS score events
        print("Capturing search results...")
        search_query = "search sourcetype=epss:score earliest=-1d@d | head 20 | table cve_id epss_score percentile epss_risk_tier score_date model_version"
        page.goto(f"{SPLUNK_URL}/en-US/app/TA-epss/search?q={search_query}")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(20)
        page.screenshot(path=f"{OUTPUT_DIR}/epss_search_results.png", full_page=True)
        print(f"  Saved {OUTPUT_DIR}/epss_search_results.png")

        # Input configuration page
        print("Capturing input configuration...")
        page.goto(f"{SPLUNK_URL}/en-US/manager/TA-epss/data/inputs/epss")
        page.wait_for_load_state("domcontentloaded")
        time.sleep(8)
        page.screenshot(path=f"{OUTPUT_DIR}/epss_input_config.png", full_page=True)
        print(f"  Saved {OUTPUT_DIR}/epss_input_config.png")

        browser.close()
        print("Done! Screenshots saved to screenshots/")


if __name__ == "__main__":
    main()
