# AIR — 멀티테넌트 쇼핑몰 · 취약 baseline (`feature/web`)

> **AIR (Automated Incident Response)** — 실시간 위협 대응 DevSecOps 자동화 팀 프로젝트.
> 본 브랜치(`feature/web`)는 공격·데모의 **대상이 되는 의도적 취약 baseline** 입니다.
> 자율방어(AIR) 계층 없이 **앱 코드 자체가 취약**합니다 → 공격이 실제로 성공합니다.
> 방어 적용본은 [`feature/air-defense`](../../tree/feature/air-defense) 입니다.

> ⚠️ **의도적으로 취약합니다.** 격리 환경/신뢰 IP 에서만 구동하세요.

---

## 기술 스택

| 영역 | 내용 |
|---|---|
| Backend | Java 21, Spring Boot 3.3.5, Spring Security + JJWT(HS512), MyBatis 3, SQLite |
| Frontend | 순수 HTML/CSS/JS (빌드 도구 없음), 해시 라우팅 SPA |
| Infra | Docker 멀티스테이지, docker-compose, nginx(정적 서빙 + `/api` 리버스 프록시) |
| CI/CD | GitHub Actions — **Semgrep(SAST) · Trivy(이미지) · ZAP(DAST) + 게이트** (취약 baseline이라 findings 리포트, `continue-on-error`로 비차단) |
| 배포 | AWS EC2 (Amazon Linux 2023), nginx `:80` |

## 아키텍처

```
[Browser] ──http──> [nginx :80] ──/────────> 정적 SPA (index.html, js, css)
                          └──/api/──proxy──> [Spring Boot :8080] ──> SQLite (volume)
```
- 단일 출처(nginx)로 프론트와 API 제공 → CORS/혼합콘텐츠 없음
- 인증: JWT Access + Refresh(회전·재사용 감지), 비밀번호 BCrypt

## ⚠️ 의도적 취약점 5종 (공격 표면)

| # | 취약점 | 엔드포인트 | 공격 |
|---|---|---|---|
| 1 | 음수수량 주문(비즈니스 로직) | `POST /api/v1/tenants/{tid}/orders` | `quantity < 0` → total 음수 → **잔액 증식** |
| 2 | SQL Injection | `GET /api/v1/tenants/{tid}/products/search?q=` | `${q}` 동적쿼리 → `' OR '1'='1` 필터 우회 |
| 3 | Stored XSS | `POST /api/v1/tenants/{tid}/products` (name) | 입력 원문 저장 → 렌더 시 스크립트 실행 |
| 4 | IDOR | `GET /api/v1/tenants/{tid}/orders/{id}` | 소유자 검증 없음 → **타인 주문 열람** |
| 5 | 파일 업로드 | `POST /api/v1/tenants/{tid}/uploads`, `GET .../uploads/download?name=` | 확장자 무검증(웹셸/저장형 XSS) + 경로조작 쓰기 + **LFI**(`/etc/passwd`) |

- 상품 페이지 UI에 **업로드 폼** 포함 → 브라우저로도 시연 가능.
- `com.shop.air` 방어 계층 미포함 → **영구 취약**(공격 성공 대상).
- 일반 하드닝(JWT fail-closed, 로그인 rate-limit, backend 8080 loopback 전용)은 유지 — 데모 대상은 위 5종.

## 역할(Role)

| 역할 | 권한 요약 |
|---|---|
| `super_admin` | 전체 테넌트/사용자 관리, 역할 변경, 관리자 배정, 감사로그, 통합 알림 |
| `admin` | 여러 테넌트 관리(다대다), 상품·주문·가입/충전요청 처리, 정산 수령 |
| `customer` | 회원가입 요청, 쇼핑/주문, 잔액 충전 요청, 본인 알림 |

## 빠른 시작

```bash
cp .env.example .env       # JWT 시크릿/ADMIN_PASSWORD 등 강하게 설정(fail-closed)
docker-compose up -d --build
# 접속: http://<호스트>/          (nginx :80)
# 헬스: curl http://localhost/api/v1/health
# 로그인: qudfhr / 3rdProject!   (super_admin)
```

## 공격 검증 (DAST)

[`feature/air-attack`](../../tree/feature/air-attack) 의 공격 스크립트를 `--base http://<호스트>:80` 으로 실행하면 5종 모두 **VULNERABLE** 로 성공합니다.
(예: `python attack.py sqli --base http://<host>:80 --admin-user qudfhr --admin-pass ...`)

## 프로젝트 구조

```
backend/   Spring Boot API (config·controller·domain·dto·mapper·security·service)
frontend/  정적 SPA + nginx (index.html, js/api.js, js/app.js)
.github/workflows/security.yml   # Semgrep/Trivy/ZAP CI
docker-compose.yml  .env.example  README.md
```

## 브랜치 구도

| 브랜치 | 성격 |
|---|---|
| **`feature/web`** (본 브랜치) | 취약 baseline — 방어 없음, **공격/데모 대상** (`:80`) |
| `feature/air-defense` | 동일 앱 + **AIR 자율방어**(탐지→차단→자동패치→Discord) (`:8081`) |
| `feature/air-attack` | DAST 공격 스크립트 세트 |
| `dev` | 보안 CI/CD 파이프라인 |

## 보안 주의

- `.env`, `*.pem`, JWT 시크릿은 **커밋 금지**(`.gitignore`).
- 본 브랜치는 의도적 취약 — **격리/신뢰 IP 전용**. 운영 노출 금지.

---
_학습/보안 실습용 테스트베드입니다._
