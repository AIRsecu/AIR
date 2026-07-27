# Swagger & Schemathesis API Security Testing

## 📌 Overview

OpenAPI Specification 기반 API 보안 테스트를 위해 Swagger(OpenAPI)와 Schemathesis를 연동합니다.

기존 보안 스캐너(Semgrep, Trivy, ZAP)는 코드 취약점, 의존성 취약점, 웹 취약점 탐지에 집중되어 있으며 API 명세 기반 요청/응답 검증에는 한계가 있습니다.

Schemathesis를 추가하여 OpenAPI 명세를 기반으로 자동 API 테스트를 수행하고, 테스트 결과를 LLM 분석용 JSON 데이터로 변환합니다.

---

## 🎯 Purpose

- OpenAPI Specification 기반 API 자동 테스트
- API Request / Response Contract 검증
- 예상하지 못한 응답 및 예외 처리 탐지
- LLM 기반 보안 분석을 위한 결과 데이터 생성

---

## 🔧 Components

### 1. Swagger / OpenAPI

Springdoc OpenAPI를 통해 Spring Boot API 명세를 생성합니다.

#### OpenAPI Document

Backend 실행 후 확인: http://localhost:8080/v3/api-docs

Swagger UI: http://localhost:8080/swagger-ui/index.html

---

### 2. Schemathesis

Schemathesis는 OpenAPI Specification을 기반으로 API 요청을 생성하고,
실제 API 응답이 명세와 일치하는지 검증하는 API Contract Testing 도구입니다.

---

#### Installation

```bash
pip install schemathesis
```

설치 확인:
```bash
schemathesis --version
```

---

#### Local Execution

Backend 실행 후 OpenAPI 명세 기반 테스트를 실행합니다.

```bash
./scripts/security/run-schemathesis.sh
```

스크립트 실행 과정:

1. OpenAPI Schema 지정
2. Schemathesis API 테스트 실행
3. JUnit XML Report 생성
4. XML 결과 JSON 변환
5. LLM 분석용 JSON 생성

수동 실행이 필요한 경우:

/
```bash
schemathesis run \
docs/openapi/openapi.json \
--url http://localhost:8080 \
--report-junit-path reports/openapi/schemathesis-report.xml
```

이유:
- 지금은 단순 schemathesis 실행이 아니라 `run-schemathesis.sh`가 기준 실행점임
- README와 실제 작업 방식 일치


---

## Directory Structure

```
.
├── docs
│   └── openapi
│       └── openapi.json
│
├── scripts
│   └── security
│       ├── run-schemathesis.sh
│       └── parse_schemathesis.py
│
└── reports
    └── openapi
        ├── schemathesis-report.xml
        └── schemathesis_for_llm.json
```


---

## Script Description
### run-schemathesis.sh

Schemathesis 실행 및 결과 저장을 담당합니다.

#### 수행 과정

1. OpenAPI Schema 지정
2. Schemathesis API 테스트 실행
3. JUnit XML Report 생성
4. XML 결과를 JSON으로 변환
5. LLM 분석용 JSON 생성

#### 생성 파일

```
reports/openapi/
├── schemathesis-report.xml
└── schemathesis_for_llm.json
```

### parse_schemathesis.py

Schemathesis JUnit XML 결과에서 LLM 분석에 필요한 정보만 추출합니다.

#### 추출정보
| Field   | Description |
| --- | --- |
| test_case | 테스트 대상 API |
| test_class | 테스트 그룹 |
| status | 테스트 실패 상태 |
| failure_type | failure/error 구분 |
| error_message | 실패 원인 |
| execution_time | 실행 시간 |

#### Noise Filtering

Schemathesis 결과 중 API 보안 분석 가치가 낮은 항목은 LLM 분석 대상에서 제외합니다.

현재 제외 대상:
- 일부 예상 가능한 HTTP Status Code 응답

예: expected 405


위 항목은 실제 API 취약점보다는 Framework의 HTTP Method 처리 정책 차이로 판단하여 제외합니다.

---

## LLM Analysis Format

#### 생성 파일

```
reports/openapi/schemathesis_for_llm.json
```

#### Example

```json
[
  {
    "test_case": "POST /api/login",
    "test_class": "schemathesis",
    "status": "failed",
    "failure_type": "failure",
    "error_message": "Response schema validation failed",
    "execution_time": "0.421"
  }
]
```

---

## 🚧 Current Status

### Completed

- Springdoc OpenAPI 설정
- OpenAPI JSON 생성 확인
- Schemathesis 실행 확인
- JUnit XML Report 생성
- Schemathesis 결과 JSON 변환
- LLM 분석용 `schemathesis_for_llm.json` 생성
- Schemathesis CI Job 분리
- Backend Container Health Check 이후 테스트 실행
- Schemathesis 결과 Artifact 저장


---

## 💡 Notes

- Schemathesis는 취약점 스캐너가 아닌 API Contract Testing 도구입니다.
- CWE, CVSS 기반 취약점 탐지보다는 OpenAPI 명세 대비 비정상 요청/응답 검증을 목적으로 합니다.
- Semgrep, Trivy, ZAP과 함께 사용하여 코드, 의존성, 웹, API 영역을 보완합니다.

### CI Execution Note

Schemathesis는 현재 CI Blocking 조건으로 사용하지 않습니다.

이유:
- 인증/인가 정책에 따른 정상적인 401/403 응답 존재
- OpenAPI Contract Drift와 실제 API 취약점을 구분할 필요 존재

현재 목적은 API Contract Test 결과 수집 및 LLM 기반 보안 분석 데이터 생성입니다.


---

이 버전은 현재 브랜치 상태 기준으로 맞췄습니다.

특히 수정한 부분:
- ❌ "CI/CD 연결 완료"처럼 보이는 표현 제거
- ❌ 아직 하지 않은 Security Gate 반영 표현 완화
- ✅ 현재 완료된 Swagger + Schemathesis + JSON 추출까지만 기록
- ✅ ZAP/Trivy/Semgrep과 같은 "LLM 분석 전처리 단계" 관점 유지

이 상태로 PR에 README 추가해도 과장 없이 맞습니다.