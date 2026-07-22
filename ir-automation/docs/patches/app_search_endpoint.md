# 패치 초안: `GET /incidents` 검색 엔드포인트

> **상태:** 초안 (IR store 4순위 산출물) — **아직 `app.py`에 미적용**  
> **작성 목적:** store 계층(`IncidentStore.find`) 완료 후, 앱/배포 담당 팀원 리뷰·머지용  
> **관련:** `ir/store/stats.py`, `ir/store/incident_store.py`

---

## 배경

4순위에서 인시던트 인덱스·통계는 **store 계층만** 구현한다.  
`app.py`는 팀원 담당 영역이므로 이 문서의 diff를 리뷰한 뒤 적용해 달라.

store API:

```python
store.find(ip: str | None = None, type: str | None = None, limit: int = 50) -> list[dict]
store.stats_snapshot() -> dict | None
```

- `find()` 락 타임아웃 시: **`[]` + warning 로그** (500 아님). store 계층은 degraded 필드를 반환하지 않음.
- 반환 `dict`는 기존 `GET /incidents/{id}` 와 동일 스키마(`load()` 결과).

---

## 제안 엔드포인트

| Method | Path | Query | 응답 |
|--------|------|-------|------|
| GET | `/incidents` | `ip`, `type`, `limit`(default 50) | 아래 옵션 A/B |

기존 `GET /incidents/{incident_id}` 와 **충돌 없음**.

### 동작

- `ip` / `type` 둘 다 없으면 → `recent(limit)` 위임(또는 400 — **팀 선택**)
- 둘 중 하나/둘 다 있으면 → `store.find(...)` (교집합)
- `limit` 상한 예: 200

### 빈 필터 시

**권장:** `ip`·`type` 모두 없으면 `recent(limit)`.

---

## 락 타임아웃 응답 — 팀 선택 (옵션 A / B)

store 는 timeout 시 `[]` 만 반환한다. “결과 없음” vs “인덱스 degraded” 구분은 **app 레이어 선택**.

### 옵션 A — 단순 (store 그대로)

```json
{ "count": 0, "items": [] }
```

로그의 `index lock timeout` 으로만 구분. 구현 단순.

### 옵션 B — degraded 힌트 (하위 호환)

소비자가 무시해도 OK. 프론트/모니터링이 “빈 결과” 오인 방지.

```json
{
  "count": 0,
  "items": [],
  "degraded": true,
  "reason": "index_lock_timeout"
}
```

구현 스케치 (app.py — **팀원 결정 후**):

```python
# store.find 가 timeout 시 [] 만 주므로, app 에서 구분하려면
# 예: StatsIndex/IncidentStore 에 last_find_degraded 플래그 추가(후속)
# 또는 당분간 옵션 A 유지
```

> 현재 store 에는 degraded 플래그가 **없음**. 옵션 B 채택 시 store에
> `find_with_status() -> tuple[list, degraded: bool]` 같은 확장 또는
> 스레드로컬 플래그가 추가로 필요 — **별도 합의**.

---

## Diff 초안 (`ir/app.py`) — 옵션 A 기준

```diff
@@ docstring endpoints @@
-    GET  /incidents/{id}  저장된 인시던트 레코드
+    GET  /incidents          검색(ip/type) 또는 최근 목록
+    GET  /incidents/{id}     저장된 인시던트 레코드

+@app.get("/incidents")
+def list_incidents(
+    ip: str | None = None,
+    type: str | None = None,
+    limit: int = 50,
+) -> dict:
+    limit = max(1, min(limit, 200))
+    if ip is None and type is None:
+        items = pipeline.store.recent(limit)
+    else:
+        items = pipeline.store.find(ip=ip, type=type, limit=limit)
+    return {"count": len(items), "items": items}
```

목록 라우트를 `{incident_id}` 보다 **먼저** 등록하거나 path 충돌 없게 유지.

---

## 테스트 초안 (팀원 쪽)

```python
def test_list_incidents_by_ip(client, ...): ...
def test_list_incidents_by_type(...): ...
def test_list_incidents_recent_when_no_filter(...): ...
```

---

## 머지 체크리스트

- [ ] store `find()` / 인덱스가 feature에 머지됨
- [ ] `INCIDENT_META_PATH` env 문서화 확인
- [ ] 옵션 A vs B 선택 후 `app.py` 적용
- [ ] TestClient 검색 스모크
- [ ] README 엔드포인트 표 갱신

---

## 범위 밖

- Discord / blocker 변경 없음
- `GET /stats` / 자동 rebuild API — 후속 티켓
