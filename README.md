# AIR — 멀티테넌트 쇼핑몰 DevSecOps 테스트베드 (Web)

> **AIR (Automated Incident Response)** — 실시간 위협 대응 DevSecOps 보안운영 자동화를 목표로 하는 팀 프로젝트.
> 본 모듈(`feature/web`)은 멀티테넌트 이커머스 위에 인증·인가, 지갑/정산, 요청 승인 워크플로우, 인앱 알림을
> 구현한 **테스트베드 웹 애플리케이션**입니다 (Spring Boot API + 빌드리스 정적 SPA).

---

## 기술 스택

| 영역 | 내용 |
|---|---|
| Backend | Java 21, Spring Boot 3.3.5, Spring Security + JJWT(HS512), MyBatis 3, SQLite |
| Frontend | 순수 HTML/CSS/JS (빌드 도구 없음), 해시 라우팅 SPA |
| Infra | Docker 멀티스테이지, docker-compose, nginx(정적 서빙 + `/api` 리버스 프록시) |
| 배포 | AWS EC2 (Amazon Linux 2023) |

## 아키텍처

```
[Browser] ──http──> [nginx :80] ──/────────> 정적 SPA (index.html, js, css)
                          └──/api/──proxy──> [Spring Boot :8080] ──> SQLite (volume)
```
- 단일 출처(nginx)로 프론트와 API를 함께 제공 → CORS/혼합콘텐츠 없음
- 인증: JWT Access(15분) + Refresh(회전·재사용 감지), 비밀번호 BCrypt

## 역할(Role)

| 역할 | 권한 요약 |
|---|---|
| `super_admin` | 전체 테넌트/사용자 관리, 역할 변경, 관리자 배정, 감사로그, 통합 알림 |
| `admin` | **여러 테넌트** 관리(생성/소유 + 배정), 상품·주문·가입/충전요청 처리, 접속주소(slug·도메인) 변경, 배송완료 정산 수령 |
| `customer` | 회원가입 요청, 쇼핑/주문, 잔액 충전 요청, 보유잔액 확인, 본인 상태변경 알림 |

## 주요 기능

- **멀티테넌트**: 테넌트(상점)별 상품/주문/고객 격리, admin↔tenant **다대다** 관리
- **인증/인가**: JWT, RBAC, refresh 토큰 회전·재사용 감지
- **회원가입 요청 워크플로우**: 고객 셀프 신청(공개) → 관리자 승인/반려 → 계정 생성
- **지갑/충전**: 고객 충전 요청 → 관리자 승인 시 잔액 반영
- **구매/정산**: 주문 시 잔액 검증·차감(원자적), 취소 시 환불·재고 복원,
  **배송완료(shipped) 시 점주(admin) 잔액 정산 입금**
- **인앱 알림(폴링)**: 관리자에게 **주문/가입/충전** 대기 알림(벨·배지·토스트),
  고객에게 **본인 주문·충전 상태변경** 알림
- **감사 로그**: 주요 행위 append-only 기록
- **무중단 스키마 마이그레이션**: 부팅 시 누락 컬럼 자동 추가(`down -v` 불필요)

## 빠른 시작

### 1) 환경변수
```bash
cp .env.example .env
# JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, ADMIN_USERNAME, ADMIN_PASSWORD 등 설정
```

### 2) Docker Compose 실행 (백엔드 + 프론트 nginx)
```bash
docker-compose up -d --build
```
- 접속: `http://<호스트>` (nginx 80)
- 헬스: `curl http://localhost/api/v1/health`

### 3) 로컬 프론트 개발 (Node 불필요)
```bash
cd frontend
python -m http.server 5173      # 또는 start-frontend.bat
# 브라우저: http://localhost:5173  (로그인 화면에서 서버 주소 입력)
```

## API 요약 (`/api/v1`)

| 영역 | 대표 엔드포인트 |
|---|---|
| 인증 | `POST /auth/login` · `POST /auth/refresh` · `POST /auth/logout` |
| 테넌트 | `GET /tenants` · `GET /tenants/managed` · `POST /tenants` · `PATCH /tenants/{id}` · `*/admins` |
| 사용자 | `GET/POST /users` · `PATCH /users/{id}`(역할/소속) · `GET /users/me` |
| 상품 | `GET/POST /tenants/{tid}/products` · `PATCH/DELETE .../{id}` |
| 주문 | `POST /tenants/{tid}/orders` · `GET .../my` · `PATCH .../{id}/status` |
| 가입요청 | `POST /tenants/{tid}/signup-requests`(공개) · `.../{id}/approve|reject` |
| 충전요청 | `POST /tenants/{tid}/charge-requests` · `.../{id}/approve|reject` |
| 알림 | `GET /notifications/pending-signups` (주문+가입+충전 대기 집계) |
| 감사 | `GET /audit/recent` · `/audit/me` |

## 프로젝트 구조

```
backend/                      # Spring Boot API
  src/main/java/com/shop/
    config/                   # Security, DataSource, MyBatis, Bootstrap, SchemaMigration
    controller/               # Auth, User, Tenant, Product, Order, Signup, Charge, Notification, Audit
    domain/                   # User, Tenant, Product, Order, SignupRequest, ChargeRequest, ...
    dto/ mapper/ security/ service/ util/
  src/main/resources/
    application.yml  schema.sql  mapper/*.xml
  Dockerfile  pom.xml
frontend/                     # 정적 SPA + nginx
  index.html  css/  js/(api.js, app.js)  nginx.conf  Dockerfile
docker-compose.yml  .env.example  README.md
```

## 보안 주의

- `.env`, `*.pem`, JWT 시크릿은 절대 커밋하지 않습니다 (`.gitignore` 처리).
- 운영/공개 노출 전 **JWT 시크릿·관리자 비밀번호를 반드시 교체**하세요.
- 공개 데모 시 보안그룹은 신뢰 IP로 제한하는 것을 권장합니다.

---
_본 저장소는 학습/테스트 목적의 테스트베드입니다._
