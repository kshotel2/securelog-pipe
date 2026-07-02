#!/usr/bin/env python3
"""
SecureLogPipe - Alert Sender
detection_report.json에서 high severity 이벤트를 읽어
Slack 또는 Discord Webhook으로 알림을 전송한다.

Usage:
    WEBHOOK_URL=https://... python detector/alert.py reports/detection_report.json

환경변수:
    WEBHOOK_URL  - Slack Incoming Webhook 또는 Discord Webhook URL
    WEBHOOK_TYPE - "slack" (기본값) 또는 "discord"
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from pathlib import Path


WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "")
WEBHOOK_TYPE = os.environ.get("WEBHOOK_TYPE", "slack").lower()


def load_detections(report_path: str) -> list[dict]:
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


def filter_high(detections: list[dict]) -> list[dict]:
    return [d for d in detections if d.get("severity", "").lower() == "high"]


def format_slack_message(event: dict) -> dict:
    text = (
        f"🚨 *[HIGH] {event['attack_type']} Detected*\n"
        f"• Rule: `{event['rule_id']}`\n"
        f"• IP: `{event['source_ip']}`\n"
        f"• Method: `{event['method']}`\n"
        f"• Path: `{event['path']}`\n"
        f"• Time: `{event['@timestamp']}`\n"
        f"• Pattern: `{event.get('matched_pattern', '-')}`"
    )
    return {"text": text}


def format_discord_message(event: dict) -> dict:
    content = (
        f"🚨 **[HIGH] {event['attack_type']} Detected**\n"
        f"Rule: `{event['rule_id']}`\n"
        f"IP: `{event['source_ip']}`\n"
        f"Method: `{event['method']}`\n"
        f"Path: `{event['path']}`\n"
        f"Time: `{event['@timestamp']}`\n"
        f"Pattern: `{event.get('matched_pattern', '-')}`"
    )
    return {"content": content}


def send_webhook(payload: dict) -> bool:
    if not WEBHOOK_URL:
        print("[WARN] WEBHOOK_URL not set. Skipping send.")
        return False

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        WEBHOOK_URL,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "SecureLogPipe/1.0"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            status = resp.status
            print(f"[OK] Webhook sent (HTTP {status})")
            return True
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP {e.code}: {e.reason}")
        return False
    except urllib.error.URLError as e:
        print(f"[ERROR] URL error: {e.reason}")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python detector/alert.py <detection_report.json>")
        sys.exit(1)

    report_path = sys.argv[1]
    if not os.path.exists(report_path):
        print(f"[ERROR] Report not found: {report_path}")
        sys.exit(1)

    detections = load_detections(report_path)
    high_events = filter_high(detections)

    print(f"[*] Total detections: {len(detections)}")
    print(f"[*] HIGH severity: {len(high_events)}")

    if not high_events:
        print("[*] No high severity events. Nothing to send.")
        return

    for event in high_events:
        print(f"[*] Sending alert: {event['rule_id']} from {event['source_ip']}")

        if WEBHOOK_TYPE == "discord":
            payload = format_discord_message(event)
        else:
            payload = format_slack_message(event)

        send_webhook(payload)


if __name__ == "__main__":
    main()
