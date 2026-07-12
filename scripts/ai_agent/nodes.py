from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from state import SastFacts, TrivyFacts, DastFacts, TriageResult, RiskAssessment, SecurityState

"""llm = ChatOpenAI(
    model="my-qwen",   # 모델명
    base_url="http://localhost:11434/v1", # Ollama 로컬 서버 주소
    api_key="ollama",
    temperature=0,
)"""
llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

# ==========================================
# [Node 1] Phase 1: Information Extractor
# ==========================================
def node_phase1_extractor(state: SecurityState) -> dict:
    scan_tool = state["scan_tool"]

    # System Prompt
    sys_prompt = f"""You are an expert DevSecOps security analyst.
Your task is to extract factual security context from the provided vulnerability data WITHOUT making final judgments.

[System Architecture Context]
{state['system_context']}
"""
    sys_msg = SystemMessage(content=sys_prompt)
    
    # 1. SAST (Semgrep, SonarQube 등) 처리
    if scan_tool == "SAST":
        prompt = f"""Extract security facts from the following SAST finding and its source code chunk:
{state['vuln_data']}
Focus heavily on identifying security decorators, sanitization logic, and the return type."""
        structured_llm = llm.with_structured_output(SastFacts)
        
    # 2. Trivy (SCA / Container) 처리
    elif scan_tool == "Trivy":
        prompt = f"""Extract security facts from the following Dependency/Container vulnerability:
{state['vuln_data']}
Focus on framework default configurations and architectural isolation that might mitigate this CVE."""
        structured_llm = llm.with_structured_output(TrivyFacts)
        
    # 3. DAST (ZAP 등) 처리
    elif scan_tool == "DAST":
        prompt = f"""Extract security facts from the following DAST alert:
{state['vuln_data']}
Focus on safe response behaviors (e.g., error handling), missing headers, and payload reflection."""
        structured_llm = llm.with_structured_output(DastFacts)
        
    # 4. Fallback (기본 예외 처리)
    else:
        prompt = f"Extract facts for: {state['vuln_data']}"
        structured_llm = llm.with_structured_output(SastFacts)

    # 지정된 스키마 출력
    extracted = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    return {"extracted_facts": extracted}

# ==========================================
# [Node 2] Phase 2: False Positive Triage
# ==========================================
def node_phase2_triage(state: SecurityState) -> dict:
    # 1. System Prompt
    sys_msg = SystemMessage(
        content="You are a highly skeptical senior security engineer. You operate on a 'Zero Trust' principle regarding automated scanner outputs. You know that SAST/DAST scanners lack architectural context and produce a massive amount of False Positives. Your default stance is to distrust the scanner's claims until proven otherwise by concrete evidence."
    )
    
    # 2. Human Prompt
    prompt = f"""Based on the extracted facts and system context, independently determine if this vulnerability is a False Positive. Do NOT blindly trust the scanner's rule description or severity.

- Scan Tool: {state['scan_tool']}
- System Context: {state['system_context']}
- Original Vulnerability Data: {state['vuln_data']}
- Phase 1 Extracted Facts: {state['extracted_facts']}

[Zero-Trust Triage Guidelines]
1. Burden of Proof: Assume the finding is a False Positive UNLESS the extracted facts show a clear, exploitable path for an external attacker.
2. Architectural Norms: Standard operational configurations or defensive implementations are NOT vulnerabilities. Mark them as False Positives.
3. The "Framework Shield" Rule: 
   - If the higher-level architecture or framework completely terminates, sanitizes, or blocks the malicious payload before it reaches the vulnerable underlying component, classify it as a False Positive.
   - HOWEVER, if the higher-level framework merely restricts parameters but still passes the payload through to the vulnerable parser, it MUST be classified as a True Positive.
   - Network isolation or internal environment status do not make a technically reachable vulnerability a False Positive.
4. Rely ONLY on the [Network & Security Perimeter] provided in the System Context. Do not presuppose absent WAFs or missing proxies.
5. Confidence Scoring: 
   - 90-100: Absolute certainty based on clear code evidence or standard architectural norms.
   - 70-89: High probability based on logical deduction.
   - Below 70: Ambiguous context requiring human review.
"""
    
    structured_llm = llm.with_structured_output(TriageResult)
    triage = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    return {"triage_result": triage}

# ==========================================
# [Node 3] Phase 3: Business Risk Assessor
# ==========================================
def node_phase3_assessor(state: SecurityState) -> dict:
    sys_msg = SystemMessage(
        content="You are a senior cybersecurity consultant evaluating business risk. Your job is to assign a final severity rating to a TRUE POSITIVE vulnerability based on its business impact and exposure."
    )
    
    prompt = f"""Evaluate the final business risk of this vulnerability.

- Scan Tool: {state['scan_tool']}
- System Context (Base OS, Tech Stack, Directory Tree): 
{state['system_context']}
- Extracted Facts: 
{state['extracted_facts']}
- Original Vulnerability Data: 
{state['vuln_data']}

[Evaluation Guidelines]
1. If the file path is related to admin, payment, or auth, increase the risk.
2. If the file path is related to tests, internal mocks, or build scripts, decrease the risk.
3. For DAST results, if sensitive data was actually leaked in the response, set to Critical or High.
4. Output MUST align with the standard CVSS logic tailored to the provided system context.
"""
    
    # 구조화된 출력 강제
    structured_llm = llm.with_structured_output(RiskAssessment)
    risk = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    return {"risk_assessment": risk}

# ==========================================
# [Node 4] Phase 4: Markdown Reporter
# ==========================================
def node_phase4_reporter(state: SecurityState) -> dict:
    triage = state["triage_result"]
    scan_tool = state.get("scan_tool", "Unknown")
    vuln_data = state.get("vuln_data", {})

    target = "Unknown Target"
    vuln_name = "Unknown Vuln"

    if scan_tool == "SAST":
        target = vuln_data.get("file_path", "Unknown Target")
        vuln_name = vuln_data.get("rule_id", "Unknown Vuln")
        
    elif scan_tool == "Trivy":
        pkg_name = vuln_data.get("package_name", "Unknown Pkg")
        target = f"{vuln_data.get('target', 'Unknown')} ({pkg_name})"
        vuln_name = vuln_data.get("cve_id", "Unknown CVE")
        
    elif scan_tool == "DAST":
        affected = vuln_data.get("affected_targets", [])
        # 여러 URL이 있을 경우 첫 번째 URL 외 N건으로 표기
        if affected:
            target = affected[0].get("url", "Unknown URL")
            if len(affected) > 1:
                target += f" (and {len(affected)-1} more)"
        vuln_name = vuln_data.get("alert_name", "Unknown Alert")

    sys_msg = SystemMessage(
        content="You are a technical writer generating concise Markdown security reports. Output ONLY the raw Markdown text. Do NOT include greetings, conversational padding, or markdown code blocks (```markdown)."
    )
    
    if triage.is_false_positive:
        # 오탐일 경우의 리포트 프롬프트
        prompt = f"""Generate a short Markdown report for a False Positive finding.
- Target: {target}
- Rule/Vuln: {vuln_name}
- Reason for False Positive: {triage.fp_reason}
- Confidence: {triage.confidence_score}%

Format Requirements:
You MUST strictly follow this exact markdown structure below without omitting any fields:

### 🛡️ [False Positive] {vuln_name} (Confidence: {triage.confidence_score}%)

**Target:** {target}  
**Reason:** <Refine and write the reason for the false positive here>
"""
    else:
        # 정탐일 경우의 리포트 프롬프트
        risk = state["risk_assessment"]
        prompt = f"""Generate a concise Markdown report for a True Positive vulnerability.
- Target: {target}
- Rule/Vuln: {vuln_name}
- Final Risk: {risk.final_risk}
- Impact Reason: {risk.impact_reason}
- Mitigation Context: {state['extracted_facts']}
- Confidence: {triage.confidence_score}%

Format Requirements:
You MUST strictly follow this exact markdown structure below without omitting any fields:

### 🚨 [True Positive - {risk.final_risk}] {vuln_name} (Confidence: {triage.confidence_score}%)

- **Target:** {target}
- **Context:** <Summarize the vulnerability and mitigation context>
- **Impact:** <State the impact reason and business risk>
- **Suggested Action:** <Provide a concise, actionable remediation step>
"""

    # 리포트는 구조화된 객체가 아니라 순수 문자열(Markdown)이므로 일반 invoke 사용
    response = llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    return {"final_report_md": response.content.strip()}

# ==========================================
# [Routing] 조건부 라우팅 로직
# ==========================================
def route_after_triage(state: SecurityState) -> str:
    """오탐(False Positive)이면 Phase 3을 건너뛰고 바로 리포트(Phase 4)로 이동합니다."""
    if state["triage_result"].is_false_positive:
        return "Phase_4"
    return "Phase_3"