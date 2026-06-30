#!/usr/bin/env python3
"""
SecureLogPipe - Elasticsearch Indexer
detection_report.json을 읽어 Elasticsearch의 security-events 인덱스에 적재한다.

Usage:
    python detector/index_to_elastic.py reports/detection_report.json

환경변수:
    ES_HOST  - Elasticsearch 호스트 (기본값: http://localhost:9200)
    ES_INDEX - 인덱스 이름 (기본값: security-events)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request
import urllib.error
from datetime import datetime, timezone


ES_HOST = os.environ.get("ES_HOST", "http://localhost:9200")
ES_INDEX = os.environ.get("ES_INDEX", "security-events")


def load_detections(report_path: str) -> list[dict]:
    with open(report_path, "r", encoding="utf-8") as f:
        return json.load(f)


def check_es_connection() -> bool:
    try:
        req = urllib.request.Request(f"{ES_HOST}/_cluster/health")
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read())
            status = data.get("status", "unknown")
            print(f"[*] Elasticsearch status: {status}")
            return status in ("green", "yellow")
    except Exception as e:
        print(f"[ERROR] Cannot connect to Elasticsearch: {e}")
        return False


def index_document(doc: dict, doc_id: str) -> bool:
    url = f"{ES_HOST}/{ES_INDEX}/_doc/{doc_id}"
    # action 필드 추가
    doc_with_action = {**doc, "action": "indexed"}
    data = json.dumps(doc_with_action).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return result.get("result") in ("created", "updated")
    except urllib.error.HTTPError as e:
        print(f"[ERROR] HTTP {e.code}: {e.read().decode()}")
        return False
    except urllib.error.URLError as e:
        print(f"[ERROR] URL error: {e.reason}")
        return False


def create_index_if_not_exists():
    """인덱스 매핑 정의 (시간 필드 타입 지정)"""
    url = f"{ES_HOST}/{ES_INDEX}"
    mapping = {
        "mappings": {
            "properties": {
                "@timestamp": {"type": "date"},
                "rule_id": {"type": "keyword"},
                "attack_type": {"type": "keyword"},
                "severity": {"type": "keyword"},
                "source_ip": {"type": "ip"},
                "method": {"type": "keyword"},
                "path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                "user_agent": {"type": "text"},
                "matched_pattern": {"type": "keyword"},
                "action": {"type": "keyword"},
            }
        }
    }
    data = json.dumps(mapping).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print(f"[*] Index '{ES_INDEX}' created.")
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        if "resource_already_exists_exception" in body:
            print(f"[*] Index '{ES_INDEX}' already exists.")
        else:
            print(f"[WARN] Index creation: HTTP {e.code}: {body}")


def main():
    if len(sys.argv) < 2:
        print("Usage: python detector/index_to_elastic.py <detection_report.json>")
        sys.exit(1)

    report_path = sys.argv[1]
    if not os.path.exists(report_path):
        print(f"[ERROR] Report not found: {report_path}")
        sys.exit(1)

    if not check_es_connection():
        print("[ERROR] Elasticsearch not reachable. Is it running?")
        sys.exit(1)

    create_index_if_not_exists()

    detections = load_detections(report_path)
    print(f"[*] Indexing {len(detections)} events to '{ES_INDEX}'...")

    success = 0
    for i, doc in enumerate(detections):
        # 고유 ID: rule_id + ip + timestamp 해시
        doc_id = f"{doc['rule_id']}-{doc['source_ip']}-{i}"
        if index_document(doc, doc_id):
            success += 1
        else:
            print(f"[WARN] Failed to index: {doc_id}")

    print(f"[*] Done. {success}/{len(detections)} events indexed.")


if __name__ == "__main__":
    main()
