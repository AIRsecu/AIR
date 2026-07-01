# AIR — 자율방어 vuln-lab (`feature/air-defense`)

> **AIR (Automated Incident Response)** — 실시간 위협 대응 DevSecOps 자동화 팀 프로젝트.
> 본 브랜치(`feature/air-defense`)는 [`feature/web`](../../tree/feature/web)의 취약 앱에
> **자율방어(AIR)** 를 얹은 적용본입니다. 공격을 스스로
> **탐지 → 즉시 차단 → 인시던트 기록 → 위험도 산정 → Discord 경고 → (자동 소스패치)** 로 대응합니다.

> ⚠️ 의도적 취약점을 포함한 **vuln-lab**. 격리 스택(`:8081`)에서 신뢰 IP 로만 구동하세요.

---

## 기술 스택

| 영역 | 내용 |
|---|---|
| Backend | Java 21, Spring Boot 3.3.5, Spring Security + JJWT, MyBatis 3, SQLite |
| AIR 방어 | `com.shop.air` (DetectionFilter · DefenseRegistry · IncidentService · DynamicRuleRegistry) |
| 오케스트레이터 | `air-orchestrator/` (Python: responder.py · knowledge.py · verify.sh) — 자동 소스패치 |
| Frontend | 순수 HTML/CSS/JS SPA (+ 🛡 **AIR IR 대시보드**) |
| Infra | Docker, docker-compose(`-p airlab`), nginx `:8081` |

## 자율방어 구조 (플래그 토글)

- 취약 코드와 방어 가드가 **한 코드베이스에 공존**. `DefenseRegistry` 플래그로 전환(**기본 OFF = 취약**).
- 공격 탐지 시 AIR 가 해당 플래그를 **즉시 ON** → 같은 요청부터 차단(자율방어 폐루프).
- DB 영속 → 재기동 후에도 방어 상태 보존.

## 방어 가드

| 플래그 | 대응 취약점 |
|---|---|
| `order.qty-guard` | 음수수량 주문(잔액 증식) |
| `sql.injection-guard` | SQL Injection (`${}` 동적쿼리) |
| `xss.input-guard` | Stored XSS |
| `authz.idor-guard` | IDOR (타인 주문 열람) |
| `ddos.rate-guard` | DDoS (요청 폭주 rate-limit) |
| `ransom.massdelete-guard` | 랜섬형 대량 삭제 |
| `upload.file-guard` | 파일 업로드 (확장자 무검증·경로조작·LFI) |
| `air.detection` / `anomaly.detection` | 시그니처 탐지 / 미지공격 이상탐지(4xx·5xx 버스트) |
| `air.shield` | 이상 출처 격리(쿨다운 차단) |

## 탐지 → 대응 폐루프

1. **DetectionFilter**(인라인): SQLi(q), XSS/음수수량(본문), DDoS/랜섬(rate), 4xx/5xx 이상탐지
   + **UploadService.autoDetect**(악성 파일명/경로조작)
2. **IncidentService.report** → ① 방어 플래그 즉시 ON ② 인시던트 기록 ③ **Risk Score** 산정 ④ **Discord 경고**
3. **air-orchestrator/responder.py** → LLM/템플릿 **자동 소스패치** → `verify.sh` 재공격 검증 → 커밋

## IR 자동대응

- **Risk Score**: 유형 → severity(CRITICAL/HIGH/MEDIUM/LOW) + score(0~100). `/air/incidents` 응답에 enrich.
  (SQLi/랜섬 95, 업로드악성 90, 음수수량/경로조작 85, IDOR 80, XSS 75, DDoS 70, 이상 50~60)
- **Discord 웹훅**: 환경변수 `AIR_DISCORD_WEBHOOK`. 인시던트마다 위험도 포함 경고를 **비동기 전송**(미설정 시 no-op).
- **IR 대시보드**: `super_admin` 로그인 → 상단 **🛡 AIR** — 방어 플래그 토글 + 인시던트(위험도 뱃지/유형/IP/조치/시각) 실시간.

## AIR 제어 API (super_admin)

```
GET  /api/v1/air/defenses                 # 방어 플래그 상태
POST /api/v1/air/defenses/{key}/enable    # / disable
GET  /api/v1/air/incidents?limit=         # severity/riskScore 포함
GET  /api/v1/air/rules  · POST · DELETE /rules/{id}   # 런타임 동적 룰
```

## 빠른 시작 (vuln-lab)

```bash
# .env: JWT_ACCESS_SECRET / JWT_REFRESH_SECRET / ADMIN_PASSWORD (강하게)
#       AIR_DISCORD_WEBHOOK=<디스코드 웹훅 URL>   (선택, IR 알림)
docker-compose -p airlab -f docker-compose.lab.yml up -d --build
# 접속: http://<호스트>:8081/     로그인: super_admin 계정(.env 의 ADMIN_USERNAME / ADMIN_PASSWORD)
```
시드 데이터: 테넌트 **`demo`**(데모상점) + 상품 4 + 데모 고객 1(계정/비번은 시드 스크립트에서 설정, 잔액 50만).

## 데모 플로우

```
1) 공격      python air-attack/attack.py <시나리오> --base http://<host>:8081 \
                    --admin-user <super_admin> --admin-pass '<password>'
2) 자율방어  탐지 → 가드 자동 ON(DEFENDED) + Discord 경고 + 대시보드 인시던트
3) (선택)    air-orchestrator/responder.py 로 자동 소스패치 시연
```
시나리오: `negative-qty · sqli · xss · idor · upload · ddos · ransom · unknown` (취약=exit1 / 방어=exit0)

## 오케스트레이터 (자동 소스패치)

- `knowledge.py` : 취약 유형별 패치 템플릿/검증(음수수량·SQLi·XSS·IDOR·**업로드**)
- `responder.py` : 인시던트 폴링 → LLM/휴리스틱 패치 → `verify.sh` 재공격 검증 → 커밋
  - 무료 데모: `responder.py --heuristic` / 실제 LLM: `AIR_LLM_PROVIDER`(anthropic|gemini|groq)

## 운영 주의

- 시연 후 **`/air/rules` 전삭제**(단일 nginx IP 환경에서 IP 차단룰이 전체차단 방지).
- `.env`, `*.pem`, 웹훅 URL은 **커밋 금지**. 의도적 취약 — 격리/신뢰 IP 전용.

## 브랜치 구도

`feature/web`(취약 baseline `:80`) ↔ **`feature/air-defense`**(자율방어 `:8081`) / `feature/air-attack`(DAST) / `dev`(CI).

---
_학습/보안 실습용 자율방어 테스트베드입니다._
