# SecureLogPipe: DevSecOps 보안 파이프라인과 Elastic 기반 웹 공격 탐지·알림 시스템

## 1. 프로젝트 주제

**SecureLogPipe: DevSecOps 보안 파이프라인과 Elastic 기반 웹 공격 탐지·알림 시스템**

**한 줄 설명:**  
간단한 웹앱에서 발생하는 공격성 요청 로그를 Python으로 탐지하고, 탐지 결과를 Elasticsearch에 저장해 Kibana로 시각화하며, 위험 이벤트는 Slack/Discord로 알림을 보내는 DevSecOps 포트폴리오 프로젝트.

---

## 2. 핵심 목표

이 프로젝트는 채용공고의 요구사항을 아래처럼 매칭한다.

| 공고 키워드 | 프로젝트 구현 내용 |
|---|---|
| 파이프라인 | GitHub Actions 기반 보안 CI/CD |
| DevSecOps | SAST, Secret Scan, Container Scan 자동화 |
| 로그 수집·분석 | Flask access log 분석 |
| 시나리오 개발 | SQLi, XSS, Path Traversal, Brute Force 탐지 룰 |
| 도구 개발 | Python 로그 탐지기 + 알림 도구 |
| 시각화 | Elasticsearch + Kibana 대시보드 |

---

## 3. 최종 아키텍처

```text
[GitHub Push]
      ↓
[GitHub Actions Security Pipeline]
      ├─ Secret Scan: Gitleaks
      ├─ SAST: Bandit or Semgrep
      ├─ Container Scan: Trivy
      └─ Detector Test

[Local Docker Demo]
      ├─ Flask Web App
      │    └─ access.log 생성
      ├─ Python Detector
      │    ├─ rules.yml 기반 탐지
      │    ├─ detection_report.json 저장
      │    ├─ Elasticsearch 적재
      │    └─ Slack/Discord 알림
      ├─ Elasticsearch
      └─ Kibana Dashboard
```

---

## 4. 기술 스택

| 영역 | 기술 |
|---|---|
| Web App | Flask |
| Container | Docker, Docker Compose |
| CI/CD | GitHub Actions |
| Secret Scan | Gitleaks |
| SAST | Bandit 또는 Semgrep |
| Image Scan | Trivy |
| Log Detection | Python |
| Rule 관리 | YAML |
| Search/Storage | Elasticsearch |
| Visualization | Kibana |
| Alert | Slack 또는 Discord Webhook |
| Report | JSON, Markdown |

---

## 5. 구현 기능

### 5.1 Flask 웹앱

엔드포인트는 단순하게 3개만 구현한다.

```text
GET  /
POST /login
GET  /search?q=
```

모든 요청을 `logs/access.log`에 기록한다.

로그 포맷:

```text
timestamp ip method path status_code user_agent
```

예시:

```text
2026-06-30T14:22:11 127.0.0.1 GET /search?q=' OR '1'='1 200 curl/8.0
```

---

### 5.2 공격 탐지 룰

탐지 룰은 `detector/rules.yml`로 관리한다.

탐지 시나리오 4개를 구현한다.

| 룰 ID | 시나리오 | Severity |
|---|---|---|
| SQLI-001 | SQL Injection 시도 탐지 | High |
| XSS-001 | XSS 시도 탐지 | Medium |
| PATH-001 | Path Traversal 시도 탐지 | High |
| BF-001 | Brute Force 로그인 시도 탐지 | High |

예시 룰:

```yaml
rules:
  - id: SQLI-001
    name: SQL Injection Attempt
    severity: high
    patterns:
      - "' OR '1'='1"
      - "UNION SELECT"
      - "1=1"

  - id: XSS-001
    name: XSS Attempt
    severity: medium
    patterns:
      - "<script>"
      - "javascript:"
      - "onerror="

  - id: PATH-001
    name: Path Traversal Attempt
    severity: high
    patterns:
      - "../"
      - "..%2f"
      - "/etc/passwd"

  - id: BF-001
    name: Brute Force Login
    severity: high
    threshold:
      path: "/login"
      count: 5
      window_seconds: 60
```

---

### 5.3 Python 로그 탐지기

파일명: `detector/detect.py`

역할:

```text
- access.log 읽기
- rules.yml 로드
- 공격 패턴 매칭
- Brute Force 임계치 탐지
- reports/detection_report.json 생성
```

탐지 결과 예시:

```json
[
  {
    "@timestamp": "2026-06-30T14:22:11",
    "rule_id": "SQLI-001",
    "attack_type": "SQL Injection Attempt",
    "severity": "high",
    "source_ip": "127.0.0.1",
    "method": "GET",
    "path": "/search?q=' OR '1'='1",
    "user_agent": "curl/8.0"
  }
]
```

---

### 5.4 Elasticsearch 적재

파일명: `detector/index_to_elastic.py`

역할:

```text
- detection_report.json 읽기
- Elasticsearch 연결
- security-events 인덱스에 탐지 이벤트 저장
```

인덱스명:

```text
security-events
```

저장 데이터 예시:

```json
{
  "@timestamp": "2026-06-30T14:22:11",
  "rule_id": "SQLI-001",
  "attack_type": "SQL Injection Attempt",
  "severity": "high",
  "source_ip": "127.0.0.1",
  "method": "GET",
  "path": "/search?q=' OR '1'='1",
  "user_agent": "curl/8.0",
  "action": "indexed"
}
```

---

### 5.5 Kibana 대시보드

대시보드는 4개 위젯만 만든다.

| 위젯 | 설명 |
|---|---|
| Total Security Events | 전체 탐지 이벤트 수 |
| Severity Distribution | high, medium 분포 |
| Attack Type Distribution | SQLi, XSS, Path Traversal, Brute Force |
| Events Over Time | 시간대별 탐지 이벤트 추이 |

선택 추가:

| 위젯 | 설명 |
|---|---|
| Top Source IP | 공격 시도 IP 순위 |

README에 `docs/kibana-dashboard.png` 캡처를 추가한다.

---

### 5.6 Slack 또는 Discord 알림

파일명: `detector/alert.py`

역할:

```text
- detection_report.json 읽기
- severity가 high인 이벤트만 필터링
- Webhook으로 알림 전송
```

환경변수:

```text
WEBHOOK_URL
```

알림 예시:

```text
[HIGH] SQL Injection Attempt Detected
IP: 127.0.0.1
Path: /search?q=' OR '1'='1
Rule: SQLI-001
```

---

### 5.7 GitHub Actions 보안 파이프라인

파일명: `.github/workflows/security-pipeline.yml`

파이프라인 단계:

```text
1. Checkout
2. Python 설치
3. 의존성 설치
4. Python syntax check
5. Bandit 또는 Semgrep SAST
6. Gitleaks Secret Scan
7. Docker image build
8. Trivy Container Scan
9. Detector 실행 테스트
10. Report artifact 업로드
```

포인트:

> 코드가 Push될 때마다 보안 스캔과 탐지기 테스트가 자동으로 실행되는 DevSecOps 파이프라인을 구현했다.

---

## 6. 디렉토리 구조

```text
secure-log-pipe/
├── app/
│   ├── app.py
│   ├── requirements.txt
│   └── Dockerfile
├── detector/
│   ├── detect.py
│   ├── alert.py
│   ├── index_to_elastic.py
│   ├── rules.yml
│   └── sample_access.log
├── logs/
│   └── access.log
├── reports/
│   └── detection_report.json
├── docs/
│   ├── architecture.png
│   ├── attack-scenarios.md
│   └── kibana-dashboard.png
├── .github/
│   └── workflows/
│       └── security-pipeline.yml
├── docker-compose.yml
├── README.md
└── .gitignore
```

---

## 7. 2일 개발 계획

## Day 1 — 탐지 시스템 완성

### 오전: 기본 웹앱 구축

할 일:

```text
- GitHub 저장소 생성
- Flask 앱 작성
- /, /login, /search 엔드포인트 구현
- logs/access.log 생성
- Dockerfile 작성
- docker-compose.yml 1차 작성
```

완료 기준:

```bash
docker compose up
```

실행 후 요청을 보내면 `logs/access.log`에 로그가 쌓인다.

---

### 오후: 로그 탐지기 개발

할 일:

```text
- detector/rules.yml 작성
- detector/detect.py 작성
- SQLi 탐지
- XSS 탐지
- Path Traversal 탐지
- Brute Force 탐지
- reports/detection_report.json 생성
```

완료 기준:

```bash
python detector/detect.py logs/access.log
```

실행 후 `reports/detection_report.json`가 생성된다.

---

### 저녁: 알림 기능 개발

할 일:

```text
- detector/alert.py 작성
- Webhook 환경변수 처리
- high severity 이벤트만 알림
- Slack 또는 Discord 알림 테스트
```

완료 기준:

```bash
python detector/alert.py reports/detection_report.json
```

실행 후 Slack/Discord에 알림이 도착한다.

---

## Day 2 — DevSecOps + Elastic 완성

### 오전: GitHub Actions 작성

할 일:

```text
- security-pipeline.yml 작성
- Bandit/Semgrep 설정
- Gitleaks 설정
- Trivy 설정
- Docker build 테스트
- detection_report.json artifact 업로드
```

완료 기준:

```text
GitHub Actions에서 security pipeline 성공 화면 캡처
```

---

### 오후: Elasticsearch + Kibana 연결

할 일:

```text
- docker-compose.yml에 Elasticsearch 추가
- docker-compose.yml에 Kibana 추가
- index_to_elastic.py 작성
- detection_report.json을 security-events 인덱스에 저장
- Kibana Data View 생성
- 대시보드 생성
```

완료 기준:

```bash
python detector/index_to_elastic.py reports/detection_report.json
```

실행 후 Kibana에서 탐지 이벤트를 확인한다.

---

### 저녁: 문서화

할 일:

```text
- README.md 작성
- docs/attack-scenarios.md 작성
- architecture.png 추가
- kibana-dashboard.png 추가
- Slack/Discord 알림 캡처 추가
- GitHub Actions 실행 결과 캡처 추가
```

완료 기준:

```text
GitHub README만 봐도 프로젝트 목적, 실행 방법, 탐지 시나리오, 결과를 이해할 수 있음.
```

---

## 8. 공격 테스트 명령어 예시

```bash
# SQL Injection
curl "http://localhost:5000/search?q=' OR '1'='1"

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# Path Traversal
curl "http://localhost:5000/search?q=../../etc/passwd"

# Brute Force
for i in {1..6}; do
  curl -X POST http://localhost:5000/login \
    -d "username=admin&password=wrong"
done
```

---

## 9. README에 넣을 핵심 설명

```text
본 프로젝트는 DevSecOps 관점에서 CI/CD 파이프라인 내 보안 검사를 자동화하고,
웹 공격 로그 기반 탐지 시나리오를 구현한 개인 포트폴리오입니다.

GitHub Actions를 통해 Secret Scan, SAST, Container Image Scan을 자동화했으며,
Flask 웹앱에서 발생한 access log를 Python 탐지기가 분석합니다.

탐지된 SQL Injection, XSS, Path Traversal, Brute Force 이벤트는
Elasticsearch에 저장되고 Kibana Dashboard로 시각화됩니다.
High severity 이벤트는 Slack/Discord Webhook을 통해 실시간 알림으로 전송됩니다.
```

---

## 10. 최종 우선순위

### 반드시 구현

```text
1. Flask 앱
2. access.log 생성
3. Python 탐지기
4. rules.yml
5. detection_report.json
6. Slack/Discord 알림
7. GitHub Actions
8. Gitleaks
9. Trivy
10. Bandit 또는 Semgrep
11. Elasticsearch 저장
12. Kibana 대시보드 캡처
13. README
```

### 시간 남으면 추가

```text
- 테스트 코드
- Markdown 리포트 자동 생성
- 탐지 룰별 상세 설명
- GitHub Actions artifact 업로드
- 아키텍처 다이어그램 예쁘게 정리
```

### 하지 말 것

```text
- Logstash
- Filebeat
- Nginx 연동
- Kubernetes
- Grafana
- 복잡한 인증 체계
- 머신러닝 탐지
- 실제 외부 대상 공격
```

---

## 11. 최종 결론

이 프로젝트는 2일 안에 하려면 이렇게 정의한다.

> Flask 로그를 Python 탐지기가 분석하고, 탐지 결과를 Elasticsearch/Kibana로 시각화하며, Slack/Discord로 알림을 보내고, GitHub Actions에서 보안 스캔을 자동화하는 DevSecOps 미니 프로젝트.

이 범위면 너무 과하지 않으면서도 채용공고 키워드가 거의 다 들어간다.
