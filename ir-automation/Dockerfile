# IR 자동대응 서비스 (FastAPI :8090 /ingest)
#   앱(IncidentService→IrForwarder)이 인시던트를 POST /ingest 로 밀어넣으면
#   위험도 산정 → TTL IP차단(mode별) → 인시던트 영속 → Discord 알림 → reconcile.
FROM python:3.12-slim

WORKDIR /app
COPY . /app

# 런타임 의존만(테스트 제외).
#  ★uvicorn 은 plain(h11) 사용 — uvicorn[standard]의 httptools 는 앱 IrForwarder 의
#   손수 만든 HTTP 요청을 엄격 파싱해 422(본문 미파싱)로 거부한다(VM 실측). h11 은 관용적.
RUN pip install --no-cache-dir \
    fastapi uvicorn pydantic requests python-dotenv tzdata

ENV PYTHONPATH=/app \
    BLOCK_MODE=simulation

EXPOSE 8090
# 헬스: GET /healthz
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8090/healthz',timeout=3).status==200 else 1)"

CMD ["uvicorn", "ir.app:app", "--host", "0.0.0.0", "--port", "8090"]
