# 핸드오프 → JHyye: security.yml 충돌 해소(union) 제안

`security.yml` 이 Digrass(인라인 AI판) ↔ JHyye(run-*.sh 분리판)로 갈려 충돌합니다
(`security.yml` + `docs/security/sec-summary.md`). **JHyye 의 run-*.sh 오케스트레이션을 베이스로**
Digrass 의 AI 스텝과 병록의 통합 스텝을 얹는 union 을 제안합니다.

- 전체 초안: [`docs/ci/security.union.yml`](../ci/security.union.yml) (참고용, 실행 안 됨)
- 실제 반영은 **JHyye 결정** — 아래 `summary` 잡 추가분만 보시면 됩니다.

## `summary` 잡에 추가할 스텝 (extract 다음)

```yaml
      # AI 재평가 — 병록 seam 경유(키 자동감지·무키 휴리스틱, 비차단)
      - name: AI re-evaluation (provider seam)
        env:
          AIR_LLM_PROVIDER: ${{ vars.AIR_LLM_PROVIDER }}
          OPENAI_API_KEY:    ${{ secrets.OPENAI_API_KEY }}
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
          GEMINI_API_KEY:    ${{ secrets.GEMINI_API_KEY }}
          GROQ_API_KEY:      ${{ secrets.GROQ_API_KEY }}
        run: |
          pip install -r scripts/ai_agent/requirements.txt
          bash scripts/llm/run-ai.sh

      # 통합 리포트(스캔 + AI + 런타임 IR → 단일)
      - run: python reports/contract/aggregate.py
      - run: |
          [ -f reports/summary/unified_report.md ] && \
            cat reports/summary/unified_report.md >> "$GITHUB_STEP_SUMMARY" || true
```

## 왜 이렇게

- **run-*.sh 유지** → JHyye 오케스트레이션 그대로.
- **AI 를 `run-ai.sh` 로 감쌈** → OPENAI 하드종속 제거. Secret 에 아무 공급자 키나 있으면 그걸 쓰고,
  없으면 휴리스틱으로 넘어가 **CI 가 무키에도 안 죽음**. (기존엔 `OPENAI_API_KEY` 없으면 실패)
- **aggregate 는 신규 파일만 호출** → 기존 로직 침해 0.
- 게이트/`continue-on-error` 는 JHyye 원안 유지.

## 침해 경계

병록은 `scripts/llm/`, `reports/contract/`, `docs/` 신규 파일만 소유합니다.
`security.yml` 편집은 JHyye 몫이며, 위는 **두 스텝 추가 제안**입니다(전면 재작성 아님).
`sec-summary.md` 충돌은 생성물 성격이라 어느 쪽 버전이든 재생성으로 수렴합니다.
