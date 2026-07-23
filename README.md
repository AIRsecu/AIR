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
schemathesis run \
docs/openapi/openapi.json \
--url http://localhost:8080
```


---

## Directory Structure

```
.
├── docs
│   └── openapi
│       └── openapi.json
│
├── scripts
│   ├── run-schemathesis.sh
│   └── parse_schemathesis.py
│
└── reports
    └── openapi
        ├── schemathesis-report.xml
        ├── schemathesis.log
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
4. 실행 로그 저장
5. XML 결과를 JSON으로 변환

#### 생성 파일

```
reports/openapi/

├── schemathesis-report.xml
└── schemathesis.log
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
-  OpenAPI JSON 생성 확인
- Schemathesis 실행 확인
- JUnit XML Report 생성
- Schemathesis 결과 JSON 변환


---

## 🚀 Next Step

- GitHub Actions security.yml 추가
- Schemathesis 결과 Artifact 업로드
- 기존 보안 파이프라인 결과와 통합 검토
- Security Gate 적용 검토


---

## 💡 Notes

- Schemathesis는 취약점 스캐너가 아닌 API Contract Testing 도구입니다.
- CWE, CVSS 기반 취약점 탐지보다는 OpenAPI 명세 대비 비정상 요청/응답 검증을 목적으로 합니다.
- Semgrep, Trivy, ZAP과 함께 사용하여 코드, 의존성, 웹, API 영역을 보완합니다.

---

이 버전은 현재 브랜치 상태 기준으로 맞췄습니다.

특히 수정한 부분:
- ❌ "CI/CD 연결 완료"처럼 보이는 표현 제거
- ❌ 아직 하지 않은 Security Gate 반영 표현 완화
- ✅ 현재 완료된 Swagger + Schemathesis + JSON 추출까지만 기록
- ✅ ZAP/Trivy/Semgrep과 같은 "LLM 분석 전처리 단계" 관점 유지

이 상태로 PR에 README 추가해도 과장 없이 맞습니다.