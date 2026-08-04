# EDR Backend API 명세서

문서 버전: v0.2.0  
기준 서버: `EDR Agent Backend`  
기준일: 2026-05-27

## 1. 개요

EDR Backend는 `edr-agent`가 생성하는 NDJSON 이벤트를 수집하고, 이벤트 히스토리 조회, 검색, 실시간 스트리밍, 심각도별 알림 조회/집계를 제공하는 REST API 서버입니다.

기본 URL 예시:

```text
http://127.0.0.1:8888
```

Swagger UI:

```text
http://127.0.0.1:8888/docs
```

OpenAPI JSON:

```text
http://127.0.0.1:8888/openapi.json
```

## 2. 인증

대부분의 API는 Bearer Token 인증이 필요합니다.

HTTP Header:

```http
Authorization: Bearer <TOKEN>
```

서버 환경변수:

| 변수 | 설명 |
|---|---|
| `EDR_API_TOKEN` | 읽기/쓰기 공통 토큰 |
| `EDR_INGEST_TOKEN` | 이벤트 수집 전용 토큰 |
| `EDR_READ_TOKEN` | 이벤트/알림 조회 전용 토큰 |
| `EDR_ADMIN_TOKEN` | 전체 권한 토큰 |
| `EDR_AUTH_REQUIRED` | 인증 사용 여부, 기본값 `true` |

권장 운영 방식:

```bash
export EDR_API_TOKEN='change-me-long-random-token'
uvicorn edr_backend.main:app --host 127.0.0.1 --port 8888
```

에이전트 연동 예시:

```bash
export EDR_AGENT_TOKEN='change-me-long-random-token'
sudo -E ./build/edr-agent \
  --rules config/rules.yaml \
  --endpoint http://127.0.0.1:8888/ingest \
  --token-env EDR_AGENT_TOKEN \
  --log /var/log/edr-agent/events.ndjson
```

## 3. 공통 응답

### 3.1 오류 응답

```json
{
  "detail": "invalid bearer token"
}
```

주요 상태 코드:

| Status | 의미 |
|---:|---|
| `200` | 성공 |
| `201` | 생성/수집 성공 |
| `400` | 잘못된 요청 |
| `401` | 인증 실패 |
| `413` | 요청 본문 또는 이벤트 개수 초과 |
| `422` | JSON 또는 스키마 검증 실패 |
| `429` | Rate limit 초과 |
| `503` | 인증 필수이나 서버 토큰 미설정 |

## 4. 데이터 모델

### 4.1 Alert

```json
{
  "id": "R-001",
  "name": "민감 경로 파일 수정",
  "sev": "high"
}
```

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `id` | string | Y | 룰 ID |
| `name` | string | Y | 룰 이름 |
| `sev` | string | Y | `critical`, `high`, `medium`, `low` |

### 4.2 Event 공통

모든 이벤트는 `type`, `ts`, `alerts`를 포함합니다.

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `type` | string | Y | 이벤트 타입 |
| `ts` | number | Y | 부팅 이후 경과 시간, 초 단위 |
| `alerts` | array | Y | 탐지 룰 목록, 없으면 `[]` |

대부분의 프로세스 기반 이벤트는 아래 필드를 추가로 포함합니다.

| 필드 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `pid` | number | Y | 이벤트 발생 프로세스 PID |
| `uid` | number | Y | 실제 UID |
| `comm` | string | Y | 프로세스 이름, 최대 15자 |

### 4.3 지원 이벤트 타입

| type | 설명 |
|---|---|
| `exec` | 프로세스 실행 |
| `file_write` | 파일 쓰기 |
| `file_delete` | 파일 삭제 |
| `file_rename` | 파일 이동/이름 변경 |
| `net_connect` | 외부 TCP/UDP 연결 |
| `net_bind` | 포트 리슨/바인드 |
| `dns` | DNS 쿼리 |
| `ptrace` | 프로세스 추적 시도 |
| `memfd` | 메모리 기반 파일 생성 |
| `memory` | RWX 메모리 할당 |
| `ns_unshare` | 네임스페이스 분리 |
| `anomaly` | 행동 이상 탐지 |
| `correlation` | 상관 분석 탐지 |

### 4.4 EventRecord

조회 API는 저장된 이벤트를 아래 구조로 반환합니다.

```json
{
  "id": 1,
  "event": {
    "type": "file_write",
    "ts": 12345.679,
    "pid": 1234,
    "uid": 1000,
    "comm": "vim",
    "path": "/etc/passwd",
    "flags": 33,
    "alerts": [
      {
        "id": "R-001",
        "name": "민감 경로 파일 수정",
        "sev": "high"
      }
    ]
  },
  "created_at": "2026-05-27T16:00:00.000Z"
}
```

## 5. API 목록

### 5.1 Health Check

```http
GET /health
```

인증: 불필요

응답:

```json
{
  "status": "ok"
}
```

### 5.2 에이전트 호환 NDJSON 수집

```http
POST /ingest
```

인증: ingest 권한 필요  
Content-Type: `application/x-ndjson`

`edr-agent --endpoint http://host:8888/ingest`와 호환되는 기본 수집 엔드포인트입니다.

요청:

```ndjson
{"type":"file_write","ts":12345.678,"pid":1234,"uid":1000,"comm":"vim","path":"/etc/passwd","flags":33,"alerts":[{"id":"R-001","name":"민감 경로 파일 수정","sev":"high"}]}
{"type":"dns","ts":12346.000,"pid":1234,"uid":1000,"comm":"curl","query":"evil.tk","server":"8.8.8.8","family":"ipv4","alerts":[{"id":"R-018c","name":"남용 TLD DNS 쿼리","sev":"medium"}]}
```

응답:

```json
{
  "accepted": 2,
  "ids": [1, 2]
}
```

curl:

```bash
curl -X POST http://127.0.0.1:8888/ingest \
  -H 'Authorization: Bearer change-me-long-random-token' \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary @/var/log/edr-agent/events.ndjson
```

### 5.3 이벤트 1건 수집

```http
POST /api/v1/events
```

인증: ingest 권한 필요  
Content-Type: `application/json`

요청:

```json
{
  "type": "file_write",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "vim",
  "path": "/etc/passwd",
  "flags": 33,
  "alerts": [
    {
      "id": "R-001",
      "name": "민감 경로 파일 수정",
      "sev": "high"
    }
  ]
}
```

응답: `EventRecord`

### 5.4 이벤트 여러 건 수집

```http
POST /api/v1/events/batch
```

인증: ingest 권한 필요  
Content-Type: `application/json`

요청:

```json
[
  {
    "type": "exec",
    "ts": 12345.678,
    "pid": 1234,
    "ppid": 1000,
    "uid": 1000,
    "comm": "bash",
    "path": "/usr/bin/bash",
    "argv": ["bash", "-c", "id"],
    "euid": 1000,
    "ld_preload": false,
    "alerts": []
  }
]
```

응답:

```json
{
  "accepted": 1,
  "ids": [1]
}
```

### 5.5 NDJSON 본문 수집

```http
POST /api/v1/events/ndjson
```

인증: ingest 권한 필요  
Content-Type: `application/x-ndjson`

`/ingest`와 동일하게 NDJSON 본문을 수집합니다. API 네임스페이스를 명확히 쓰고 싶을 때 사용합니다.

응답:

```json
{
  "accepted": 2,
  "ids": [1, 2]
}
```

### 5.6 이벤트 히스토리 조회 및 검색

```http
GET /api/v1/events
```

인증: read 권한 필요

Query Parameters:

| 이름 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `type` | string | N | 이벤트 타입 필터 |
| `severity` | string | N | 최소 심각도 필터 |
| `alerts_only` | boolean | N | 알림 있는 이벤트만 조회 |
| `pid` | number | N | PID 필터 |
| `uid` | number | N | UID 필터 |
| `comm` | string | N | 프로세스 이름 필터 |
| `rule_id` | string | N | 룰 ID 필터 |
| `q` | string | N | JSON 원문 부분 문자열 검색 |
| `ts_from` | number | N | 시작 timestamp |
| `ts_to` | number | N | 종료 timestamp |
| `limit` | number | N | 기본 `100`, 최대 `1000` |
| `offset` | number | N | 기본 `0` |
| `sort` | string | N | `desc` 또는 `asc`, 기본 `desc` |

요청 예시:

```bash
curl 'http://127.0.0.1:8888/api/v1/events?severity=medium&q=/etc/passwd&limit=50' \
  -H 'Authorization: Bearer change-me-long-random-token'
```

응답:

```json
{
  "items": [
    {
      "id": 1,
      "event": {
        "type": "file_write",
        "ts": 12345.679,
        "pid": 1234,
        "uid": 1000,
        "comm": "vim",
        "path": "/etc/passwd",
        "flags": 33,
        "alerts": [
          {
            "id": "R-001",
            "name": "민감 경로 파일 수정",
            "sev": "high"
          }
        ]
      },
      "created_at": "2026-05-27T16:00:00.000Z"
    }
  ],
  "total": 1,
  "limit": 50,
  "offset": 0
}
```

### 5.7 이벤트 상세 조회

```http
GET /api/v1/events/{event_id}
```

인증: read 권한 필요

응답: `EventRecord`

404 응답:

```json
{
  "detail": "event not found"
}
```

### 5.8 실시간 이벤트 스트림

```http
GET /api/v1/events/stream
```

인증: read 권한 필요  
응답 타입: `text/event-stream`

Query Parameters:

| 이름 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `type` | string | N | 이벤트 타입 필터 |
| `severity` | string | N | 최소 심각도 필터 |
| `alerts_only` | boolean | N | 알림 있는 이벤트만 스트리밍 |

curl:

```bash
curl -N 'http://127.0.0.1:8888/api/v1/events/stream?alerts_only=true' \
  -H 'Authorization: Bearer change-me-long-random-token'
```

SSE 메시지 예시:

```text
id: 1
event: file_write
data: {"id":1,"event":{"type":"file_write","ts":12345.679,"pid":1234,"uid":1000,"comm":"vim","path":"/etc/passwd","flags":33,"alerts":[{"id":"R-001","name":"민감 경로 파일 수정","sev":"high"}]},"created_at":"2026-05-27T16:00:00.000Z"}
```

### 5.9 알림 조회

```http
GET /api/v1/alerts
```

인증: read 권한 필요

Query Parameters:

| 이름 | 타입 | 필수 | 설명 |
|---|---|---|---|
| `severity` | string | N | 최소 심각도 필터 |
| `rule_id` | string | N | 룰 ID 필터 |
| `limit` | number | N | 기본 `100`, 최대 `1000` |
| `offset` | number | N | 기본 `0` |

요청:

```bash
curl 'http://127.0.0.1:8888/api/v1/alerts?severity=high' \
  -H 'Authorization: Bearer change-me-long-random-token'
```

응답:

```json
[
  {
    "event_id": 1,
    "type": "file_write",
    "ts": 12345.679,
    "pid": 1234,
    "uid": 1000,
    "comm": "vim",
    "alert": {
      "id": "R-001",
      "name": "민감 경로 파일 수정",
      "sev": "high"
    },
    "created_at": "2026-05-27T16:00:00.000Z"
  }
]
```

### 5.10 심각도별 알림 집계

```http
GET /api/v1/alerts/summary
```

인증: read 권한 필요

응답:

```json
{
  "items": [
    {
      "severity": "critical",
      "count": 1
    },
    {
      "severity": "high",
      "count": 2
    },
    {
      "severity": "medium",
      "count": 4
    },
    {
      "severity": "low",
      "count": 0
    }
  ]
}
```

## 6. 이벤트 타입별 요청 예시

### 6.1 exec

```json
{
  "type": "exec",
  "ts": 12345.678,
  "pid": 1234,
  "ppid": 1000,
  "uid": 1000,
  "comm": "bash",
  "path": "/usr/bin/bash",
  "argv": ["bash", "-c", "id"],
  "euid": 1000,
  "ld_preload": false,
  "alerts": []
}
```

### 6.2 file_write

```json
{
  "type": "file_write",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "vim",
  "path": "/etc/passwd",
  "flags": 33,
  "alerts": [
    {
      "id": "R-001",
      "name": "민감 경로 파일 수정",
      "sev": "high"
    }
  ]
}
```

### 6.3 file_rename

```json
{
  "type": "file_rename",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 0,
  "comm": "mv",
  "path": "/tmp/evil",
  "dst": "/usr/bin/evil",
  "flags": 0,
  "alerts": []
}
```

### 6.4 net_connect

```json
{
  "type": "net_connect",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "curl",
  "dst": "203.0.113.1",
  "dport": 4444,
  "family": "ipv4",
  "alerts": [
    {
      "id": "R-006",
      "name": "비표준 포트 아웃바운드",
      "sev": "medium"
    }
  ]
}
```

### 6.5 dns

```json
{
  "type": "dns",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "curl",
  "query": "evil.tk",
  "server": "8.8.8.8",
  "family": "ipv4",
  "alerts": [
    {
      "id": "R-018c",
      "name": "남용 TLD DNS 쿼리",
      "sev": "medium"
    }
  ]
}
```

### 6.6 ptrace

```json
{
  "type": "ptrace",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "gdb",
  "target_pid": 999,
  "request": 16,
  "alerts": [
    {
      "id": "R-014",
      "name": "ptrace ATTACH 의심",
      "sev": "high"
    }
  ]
}
```

### 6.7 memfd

```json
{
  "type": "memfd",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "malware",
  "name": "payload",
  "flags": 3,
  "sealing": true,
  "alerts": [
    {
      "id": "R-017",
      "name": "memfd_create 파일리스 실행",
      "sev": "high"
    }
  ]
}
```

### 6.8 memory

```json
{
  "type": "memory",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "exploit",
  "prot": 7,
  "is_mprotect": false,
  "alerts": [
    {
      "id": "R-016",
      "name": "RWX 메모리 할당",
      "sev": "high"
    }
  ]
}
```

### 6.9 ns_unshare

```json
{
  "type": "ns_unshare",
  "ts": 12345.678,
  "pid": 1234,
  "uid": 1000,
  "comm": "unshare",
  "ns_inum": 4026531836,
  "flags": "0x10000000",
  "in_container": true,
  "alerts": [
    {
      "id": "R-024",
      "name": "네임스페이스 탈출 시도",
      "sev": "high"
    }
  ]
}
```

### 6.10 anomaly

현재 에이전트의 `anomaly` 이벤트는 `pid`, `uid` 없이도 수집 가능합니다.

```json
{
  "type": "anomaly",
  "ts": 12345.678,
  "comm": "python3",
  "metric": "net_connect",
  "observed": 87.0,
  "mean": 3.2,
  "stddev": 1.5,
  "zscore": 4.23,
  "alerts": [
    {
      "id": "R-028",
      "name": "행동 이상 탐지 (EWMA 기반)",
      "sev": "high"
    }
  ]
}
```

### 6.11 correlation

```json
{
  "type": "correlation",
  "ts": 1234.59,
  "pid": 1234,
  "comm": "evil",
  "alerts": [
    {
      "id": "R-020",
      "name": "드로퍼 C2 체인: /tmp 실행 후 아웃바운드 연결",
      "sev": "critical"
    }
  ]
}
```

## 7. 제한값

기본 제한값:

| 항목 | 기본값 |
|---|---:|
| 요청 본문 크기 | `2 MiB` |
| Batch 이벤트 수 | `1000` |
| NDJSON 라인 수 | `1000` |
| SSE 연결 수 | `100` |
| Ingest rate limit | 분당 `600` |
| Read rate limit | 분당 `300` |

관련 환경변수:

| 변수 | 기본값 |
|---|---:|
| `EDR_MAX_BODY_BYTES` | `2097152` |
| `EDR_MAX_BATCH_EVENTS` | `1000` |
| `EDR_MAX_NDJSON_LINES` | `1000` |
| `EDR_MAX_SSE_CLIENTS` | `100` |
| `EDR_RATE_LIMIT_INGEST` | `600` |
| `EDR_RATE_LIMIT_READ` | `300` |

