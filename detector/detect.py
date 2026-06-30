#!/usr/bin/env python3
"""
SecureLogPipe - Log Detector
access.log를 읽어 rules.yml 기반으로 공격 패턴을 탐지하고
reports/detection_report.json을 생성한다.

Usage:
    python detector/detect.py logs/access.log
"""

from __future__ import annotations

import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml


RULES_PATH = Path(__file__).parent / "rules.yml"
REPORTS_DIR = Path("reports")


def load_rules(path: Path) -> list[dict]:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data.get("rules", [])


def parse_log_line(line: str) -> dict | None:
    """
    로그 포맷: timestamp ip method path status_code user_agent
    user_agent는 공백 포함 가능하므로 split(None, 5) 사용
    """
    line = line.strip()
    if not line:
        return None
    parts = line.split(None, 5)
    if len(parts) < 5:
        return None
    return {
        "timestamp": parts[0],
        "ip": parts[1],
        "method": parts[2],
        "path": parts[3],
        "status_code": parts[4],
        "user_agent": parts[5] if len(parts) > 5 else "-",
    }


def check_pattern_rules(entry: dict, rules: list[dict]) -> list[dict]:
    """패턴 기반 룰(SQLI, XSS, PATH) 탐지"""
    detections = []
    path_lower = entry["path"].lower()

    for rule in rules:
        if "patterns" not in rule:
            continue
        for pattern in rule["patterns"]:
            if pattern.lower() in path_lower:
                detections.append({
                    "@timestamp": entry["timestamp"],
                    "rule_id": rule["id"],
                    "attack_type": rule["name"],
                    "severity": rule["severity"],
                    "source_ip": entry["ip"],
                    "method": entry["method"],
                    "path": entry["path"],
                    "user_agent": entry["user_agent"],
                    "matched_pattern": pattern,
                })
                break  # 룰당 하나만 매칭

    return detections


def check_brute_force(entries: list[dict], bf_rule: dict) -> list[dict]:
    """BF-001: 시간 윈도우 내 동일 IP의 /login POST 횟수 탐지"""
    threshold = bf_rule.get("threshold", {})
    target_path = threshold.get("path", "/login")
    target_method = threshold.get("method", "POST")
    count_limit = threshold.get("count", 5)
    window_sec = threshold.get("window_seconds", 60)

    # ip -> 타임스탬프 리스트
    login_attempts: dict[str, list[datetime]] = defaultdict(list)

    for entry in entries:
        if entry["method"] == target_method and entry["path"].startswith(target_path):
            try:
                ts = datetime.fromisoformat(entry["timestamp"])
            except ValueError:
                continue
            login_attempts[entry["ip"]].append((ts, entry))

    detections = []
    for ip, attempts in login_attempts.items():
        attempts.sort(key=lambda x: x[0])
        # 슬라이딩 윈도우 검사
        for i in range(len(attempts)):
            window = [
                a for a in attempts[i:]
                if (a[0] - attempts[i][0]).total_seconds() <= window_sec
            ]
            if len(window) >= count_limit:
                trigger_entry = window[-1][1]
                detections.append({
                    "@timestamp": trigger_entry["timestamp"],
                    "rule_id": bf_rule["id"],
                    "attack_type": bf_rule["name"],
                    "severity": bf_rule["severity"],
                    "source_ip": ip,
                    "method": trigger_entry["method"],
                    "path": trigger_entry["path"],
                    "user_agent": trigger_entry["user_agent"],
                    "matched_pattern": f"{len(window)} requests in {window_sec}s",
                })
                break  # IP당 한 번만 리포트

    return detections


def deduplicate(detections: list[dict]) -> list[dict]:
    """동일 (rule_id, source_ip, path) 중복 제거"""
    seen = set()
    result = []
    for d in detections:
        key = (d["rule_id"], d["source_ip"], d["path"])
        if key not in seen:
            seen.add(key)
            result.append(d)
    return result


def run(log_path: str) -> list[dict]:
    rules = load_rules(RULES_PATH)
    pattern_rules = [r for r in rules if "patterns" in r]
    bf_rules = [r for r in rules if "threshold" in r]

    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            entry = parse_log_line(line)
            if entry:
                entries.append(entry)

    detections = []
    for entry in entries:
        detections.extend(check_pattern_rules(entry, pattern_rules))

    for bf_rule in bf_rules:
        detections.extend(check_brute_force(entries, bf_rule))

    detections = deduplicate(detections)
    # 타임스탬프 순 정렬
    detections.sort(key=lambda x: x["@timestamp"])

    return detections


def save_report(detections: list[dict]) -> Path:
    REPORTS_DIR.mkdir(exist_ok=True)
    report_path = REPORTS_DIR / "detection_report.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(detections, f, indent=2, ensure_ascii=False)
    return report_path


def main():
    if len(sys.argv) < 2:
        print("Usage: python detector/detect.py <log_file>")
        sys.exit(1)

    log_path = sys.argv[1]
    if not os.path.exists(log_path):
        print(f"[ERROR] Log file not found: {log_path}")
        sys.exit(1)

    print(f"[*] Analyzing: {log_path}")
    detections = run(log_path)

    report_path = save_report(detections)
    print(f"[*] Detections: {len(detections)}")
    print(f"[*] Report saved: {report_path}")

    # 심각도별 요약
    severity_count: dict[str, int] = defaultdict(int)
    for d in detections:
        severity_count[d["severity"]] += 1

    for severity, count in sorted(severity_count.items()):
        print(f"    {severity.upper()}: {count}")


if __name__ == "__main__":
    main()
