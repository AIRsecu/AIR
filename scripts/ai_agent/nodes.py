from langchain_openai import ChatOpenAI
from langchain_core.messages import SystemMessage, HumanMessage
from state import ExtractedFacts, TriageResult, RiskAssessment, SecurityState

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

# ==========================================
# [Node 1] Phase 1: Information Extractor
# ==========================================
def node_phase1_extractor(state: SecurityState) -> dict:
    scan_tool = state["scan_tool"]
    
    # 1. System Prompt
    sys_prompt = f"""You are an expert DevSecOps security analyst.
Your task is to extract factual security context from the provided vulnerability data WITHOUT making final judgments.

[System Architecture Context]
{state['system_context']}
"""
    sys_msg = SystemMessage(content=sys_prompt)
    
    # 2. Human Prompt based on the tool
    if scan_tool == "SAST":
        prompt = f"""Extract security facts from the following SAST finding and its source code chunk:
{state['vuln_data']}
Focus heavily on identifying security decorators, sanitization logic, and the return type."""
    
    elif scan_tool == "DAST":
        prompt = f"""Extract security facts from the following DAST alert:
{state['vuln_data']}
Focus on the affected URL, HTTP method, attack payload (if any), and how the server responded."""
    
    elif scan_tool == "Trivy":
        prompt = f"""Extract security facts from the following Dependency/Container vulnerability:
{state['vuln_data']}
Focus on whether the vulnerable component is actively utilized within the given system context."""
    else:
        prompt = f"Extract security facts for: {state['vuln_data']}"
        
    # 구조화된 출력 강제
    structured_llm = llm.with_structured_output(ExtractedFacts)
    extracted = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    return {"extracted_facts": extracted}

# ==========================================
# [Node 2] Phase 2: False Positive Triage
# ==========================================
def node_phase2_triage(state: SecurityState) -> dict:
    # 1. System Prompt
    sys_msg = SystemMessage(
        content="You are a strict and logical security triager. Your only job is to determine if a reported vulnerability is a False Positive (safe) or a True Positive."
    )
    
    # 2. Human Prompt
    prompt = f"""Based on the extracted facts, carefully determine if this vulnerability is a False Positive.

- Scan Tool: {state['scan_tool']}
- Original Vulnerability Data: {state['vuln_data']}
- Phase 1 Extracted Facts: {state['extracted_facts']}

[Triage Guidelines]
1. If the 'sanitization_logic' effectively mitigates the issue (e.g., type casting, escaping), mark as False Positive.
2. If the code is clearly for testing, dummy data, or timing attack prevention (e.g., hardcoded dummy bcrypt hash), mark as False Positive.
3. For DAST, if the server responded safely (e.g., 403 Forbidden or handled 500 error without leaking sensitive data), mark as False Positive.
4. Otherwise, mark as True Positive.
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
    
    sys_msg = SystemMessage(
        content="You are a technical writer generating concise Markdown security reports. Output ONLY the raw Markdown text. Do NOT include greetings, conversational padding, or markdown code blocks (```markdown)."
    )
    
    if triage.is_false_positive:
        # 오탐일 경우의 리포트 프롬프트
        prompt = f"""Generate a short Markdown report for a False Positive finding.
- Target: {state.get('vuln_data', {}).get('file_path', 'Unknown Target')}
- Rule/Vuln: {state.get('vuln_data', {}).get('rule_id', 'Unknown Vuln')}
- Reason for False Positive: {triage.fp_reason}

Format Requirements:
Use a header like `### 🛡️ [False Positive] <Rule Name>` and briefly state the reason."""
    else:
        # 정탐일 경우의 리포트 프롬프트
        risk = state["risk_assessment"]
        prompt = f"""Generate a concise Markdown report for a True Positive vulnerability.
- Target: {state.get('vuln_data', {}).get('file_path', 'Unknown Target')}
- Rule/Vuln: {state.get('vuln_data', {}).get('rule_id', 'Unknown Vuln')}
- Final Risk: {risk.final_risk}
- Impact Reason: {risk.impact_reason}
- Mitigation Context: {state['extracted_facts']}

Format Requirements:
Use a header like `### 🚨 [True Positive - {risk.final_risk}] <Rule Name>`, followed by 'Context', 'Impact', and 'Suggested Action' bullet points."""

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