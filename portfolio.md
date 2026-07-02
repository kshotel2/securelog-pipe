# SecureLogPipe — DevSecOps 보안 파이프라인 포트폴리오

## 프로젝트 개요

Flask 웹앱에서 발생하는 HTTP 요청 로그를 Python 탐지기가 실시간으로 분석해 SQL Injection, XSS, Path Traversal, Brute Force를 탐지하고, 결과를 Elasticsearch에 저장해 Kibana로 시각화하며, 위험 이벤트는 Slack/Discord Webhook으로 알림을 전송하는 DevSecOps 미니 파이프라인 프로젝트입니다.

GitHub Push가 발생할 때마다 Secret Scan, SAST, Container Image Scan이 자동으로 실행되는 보안 CI/CD 파이프라인도 함께 구축했습니다.

---

## 기술 스택

| 영역 | 기술 |
|---|---|
| Web App | Python, Flask |
| Container | Docker, Docker Compose |
| CI/CD | GitHub Actions |
| Secret Scan | Gitleaks |
| SAST | Bandit |
| Image Scan | Trivy |
| Log Detection | Python (YAML 룰 기반) |
| Storage | Elasticsearch 8.x |
| Visualization | Kibana |
| Alert | Slack / Discord Webhook |

---

## 아키텍처

```
[GitHub Push]
      ↓
[GitHub Actions — Security Pipeline]
      ├─ SAST: Bandit
      ├─ Secret Scan: Gitleaks
      ├─ Container Scan: Trivy
      └─ Detector 자동 테스트

[Local Docker Demo]
      ├─ Flask Web App          ─── access.log 생성
      ├─ Python Detector        ─── rules.yml 기반 패턴/임계치 탐지
      │    ├─ detection_report.json
      │    ├─ Elasticsearch 적재
      │    └─ Slack/Discord 알림
      ├─ Elasticsearch 8.x
      └─ Kibana Dashboard
```

---

## 개발 과정 (2일)

### Day 1 — 탐지 시스템 구축

#### 오전: Flask 웹앱 + Docker 환경 구성

웹 공격이 발생하는 환경을 먼저 구축했습니다.

Flask로 `GET /`, `POST /login`, `GET /search` 세 가지 엔드포인트를 구현하고, 모든 요청을 `logs/access.log`에 기록하도록 커스텀 로거를 설정했습니다.

```
로그 포맷: timestamp ip method path status_code user_agent
예시: 2026-06-30T14:22:11 127.0.0.1 GET /search?q=' OR '1'='1 200 curl/8.0
```

Flask 앱을 컨테이너로 실행하기 위해 `Dockerfile`을 작성하고, `docker-compose.yml`에 webapp 서비스를 정의했습니다. `volumes`로 컨테이너 내부의 `logs/`를 호스트와 공유해 탐지기가 로그 파일에 직접 접근할 수 있도록 했습니다.

**완료 기준:** `docker compose up` → 공격 요청 전송 → `logs/access.log`에 로그 적재 확인

---

#### 오후: Python 로그 탐지기 개발

탐지 규칙을 코드에서 분리해 `detector/rules.yml`로 관리했습니다. 패턴 기반 룰(SQLi, XSS, Path Traversal)과 임계치 기반 룰(Brute Force)을 구분해 정의했습니다.

```yaml
# 패턴 기반 예시
- id: SQLI-001
  name: SQL Injection Attempt
  severity: high
  patterns:
    - "' OR '"
    - "UNION SELECT"

# 임계치 기반
- id: BF-001
  name: Brute Force Login
  severity: high
  threshold:
    path: "/login"
    method: "POST"
    count: 5
    window_seconds: 60
```

`detector/detect.py`는 두 가지 탐지 로직을 분리해 구현했습니다.

- **패턴 매칭:** `path` 필드에 룰의 패턴이 포함되면 즉시 탐지 이벤트 생성
- **Brute Force 감지:** 슬라이딩 윈도우 알고리즘으로 동일 IP의 `/login POST` 요청 수가 60초 내 5회 이상이면 탐지

중복 이벤트는 `(rule_id, source_ip, path)` 조합으로 필터링해 리포트 품질을 높였습니다.

탐지 결과는 `reports/detection_report.json`으로 저장됩니다.

```json
{
  "@timestamp": "2026-06-30T14:22:11",
  "rule_id": "SQLI-001",
  "attack_type": "SQL Injection Attempt",
  "severity": "high",
  "source_ip": "127.0.0.1",
  "method": "GET",
  "path": "/search?q=' OR '1'='1",
  "matched_pattern": "' OR '"
}
```

**완료 기준:** `python detector/detect.py logs/access.log` → `reports/detection_report.json` 생성 확인

---

#### 저녁: Slack / Discord 알림 연동

`detector/alert.py`는 `detection_report.json`에서 `severity: high` 이벤트만 필터링해 Webhook으로 전송합니다.

외부 라이브러리 없이 Python 표준 라이브러리 `urllib`만으로 구현했고, `WEBHOOK_TYPE` 환경변수로 Slack과 Discord 포맷을 전환할 수 있도록 설계했습니다.

```bash
# Slack
WEBHOOK_URL=https://hooks.slack.com/... python detector/alert.py reports/detection_report.json

# Discord
WEBHOOK_URL=https://discord.com/api/webhooks/... WEBHOOK_TYPE=discord python detector/alert.py reports/detection_report.json
```

알림 예시:
```
🚨 [HIGH] SQL Injection Attempt Detected
Rule: SQLI-001
IP: 127.0.0.1
Path: /search?q=' OR '1'='1
```

**완료 기준:** 실행 후 Slack/Discord 채널에 알림 수신 확인

---

### Day 2 — DevSecOps 파이프라인 + Elasticsearch 연동

#### 오전: GitHub Actions 보안 파이프라인 구축

`.github/workflows/security-pipeline.yml`에 7단계 보안 파이프라인을 작성했습니다.

| 단계 | 도구 | 역할 |
|---|---|---|
| 1 | Python syntax check | 문법 오류 조기 발견 |
| 2 | Bandit | Python 코드 정적 분석 (SAST) |
| 3 | Gitleaks | Git 히스토리 전체 시크릿 스캔 |
| 4 | Docker build | Flask 앱 이미지 빌드 |
| 5 | Trivy | 컨테이너 이미지 취약점 스캔 |
| 6 | Detector Test | `sample_access.log`로 탐지기 동작 검증 |
| 7 | Artifact 업로드 | `detection_report.json`, `bandit-report.txt` 보존 |

Gitleaks는 `fetch-depth: 0`으로 전체 커밋 히스토리를 스캔합니다. Trivy의 `exit-code: 0` 설정으로 취약점이 발견되더라도 파이프라인이 중단되지 않고 결과를 리포트로 출력하도록 했습니다(포트폴리오 데모 목적).

**완료 기준:** GitHub Actions에서 Security Pipeline 성공 화면 캡처

---

#### 오후: Elasticsearch + Kibana 연동

`docker-compose.yml`에 Elasticsearch와 Kibana 서비스를 추가했습니다. Elasticsearch는 `xpack.security.enabled=false`로 인증 없이 로컬 데모 환경을 구성했고, `healthcheck`를 설정해 Kibana가 Elasticsearch가 정상 기동된 후에만 시작되도록 의존성을 제어했습니다.

`detector/index_to_elastic.py`는 인덱스 생성 시 `@timestamp`(date), `source_ip`(ip), `severity`(keyword) 등 명시적 타입 매핑을 정의해 Kibana에서 즉시 필터·집계가 가능하도록 했습니다.

```python
# 인덱스 매핑 핵심
"@timestamp": {"type": "date"},
"source_ip":  {"type": "ip"},
"severity":   {"type": "keyword"},
```

문서 ID는 `{rule_id}-{source_ip}-{index}` 형태로 생성해 멱등성(idempotency)을 확보했습니다. 같은 리포트를 재실행해도 중복 문서가 생성되지 않습니다.

Kibana에서는 `security-events` Data View를 생성하고 4개의 시각화 위젯으로 대시보드를 구성했습니다.

| 위젯 | 내용 |
|---|---|
| Total Security Events | 전체 탐지 이벤트 수 (Metric) |
| Severity Distribution | High / Medium 비율 (Pie Chart) |
| Attack Type Distribution | 공격 유형별 빈도 (Bar Chart) |
| Events Over Time | 시간대별 이벤트 추이 (Line Chart) |

**완료 기준:** `python detector/index_to_elastic.py reports/detection_report.json` → Kibana 대시보드에서 이벤트 시각화 확인

---

#### 저녁: 문서화

`README.md`에 아키텍처 다이어그램, 탐지 시나리오 테이블, 실행 방법, 공격 트래픽 생성 명령어, Kibana 대시보드 캡처를 포함해 README만으로 프로젝트 목적·실행·결과를 이해할 수 있도록 작성했습니다.

---

## 탐지 시나리오

| Rule ID | 공격 유형 | Severity | 탐지 방식 |
|---|---|---|---|
| SQLI-001 | SQL Injection | High | URL 쿼리에 `' OR '`, `UNION SELECT` 등 패턴 포함 여부 |
| XSS-001 | XSS | Medium | URL 쿼리에 `<script>`, `javascript:` 등 패턴 포함 여부 |
| PATH-001 | Path Traversal | High | URL 경로에 `../`, `/etc/passwd` 등 패턴 포함 여부 |
| BF-001 | Brute Force | High | 동일 IP가 60초 내 `/login POST` 5회 이상 시도 |

---

## 공격 트래픽 생성 예시

```bash
# SQL Injection
curl "http://localhost:5000/search?q=' OR '1'='1"

# XSS
curl "http://localhost:5000/search?q=<script>alert(1)</script>"

# Path Traversal
curl "http://localhost:5000/search?q=../../etc/passwd"

# Brute Force (6회 반복)
for i in {1..6}; do
  curl -X POST http://localhost:5000/login \
    -d "username=admin&password=wrong"
done
```

---

## 디렉토리 구조

```
SecureLogPipe/
├── app/
│   ├── app.py                    # Flask 웹앱
│   ├── requirements.txt
│   └── Dockerfile
├── detector/
│   ├── rules.yml                 # 탐지 룰 정의
│   ├── detect.py                 # 로그 탐지기
│   ├── alert.py                  # Slack/Discord 알림
│   ├── index_to_elastic.py       # Elasticsearch 적재
│   └── sample_access.log         # CI 테스트용 샘플 로그
├── logs/
│   └── access.log
├── reports/
│   └── detection_report.json
├── docs/
│   └── kibana-dashboard.png
├── .github/
│   └── workflows/
│       └── security-pipeline.yml
├── docker-compose.yml
└── README.md
```

---

## 핵심 구현 포인트

**규칙 기반 탐지 엔진 설계**
패턴 룰과 임계치 룰을 YAML로 분리 관리해 코드 수정 없이 탐지 규칙을 추가·수정할 수 있는 구조로 설계했습니다. 실제 보안 솔루션의 Sigma 룰, Snort 룰과 동일한 설계 철학입니다.

**슬라이딩 윈도우 Brute Force 탐지**
단순 카운트가 아닌 슬라이딩 윈도우 알고리즘을 적용해 시간 범위 내 요청 집중 패턴을 정확히 탐지합니다. IP당 첫 번째 탐지 이벤트만 리포트해 노이즈를 최소화했습니다.

**외부 의존성 없는 알림 구현**
`requests` 라이브러리 없이 Python 표준 라이브러리 `urllib`만으로 Webhook 연동을 구현했습니다. 환경변수 하나로 Slack/Discord 포맷을 전환할 수 있어 유연성을 확보했습니다.

**Elasticsearch 인덱스 매핑 최적화**
동적 매핑에 의존하지 않고 명시적 타입 매핑을 정의해 `source_ip` 필드를 ip 타입으로 저장, Kibana에서 IP 범위 검색과 집계가 즉시 동작하도록 했습니다.

**보안 CI/CD 자동화**
코드 품질(Bandit SAST), 시크릿 노출(Gitleaks), 컨테이너 취약점(Trivy) 세 가지 보안 레이어를 GitHub Actions 단일 파이프라인에 통합했습니다. 탐지기 자체도 CI에서 자동 테스트되어 규칙 변경 시 회귀를 방지합니다.
