import json
from langchain_openai import ChatOpenAI
from llm.provider import make_chat_llm
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_core.messages import SystemMessage, HumanMessage, ToolMessage

from state import (
    AuditTrail,
    SecurityState, 
    InvestigationResult, 
    TriageResult, 
    RootCauseAnalysis, 
    LogicValidationResult,
    RemediationValidationResult, 
    RiskAssessment
)
from tools import search_files, read_file_range

# ==========================================
# 0. Global Setup
# ==========================================
# 도구 탐색은 약간의 창의성이 필요하므로 temp 0.1, 판결/분석은 0 설정
"""llm_agent= ChatOpenAI(
    model="my-qwen",   # 모델명 (Qwen3.6:35B)
    base_url="http://localhost:11434/v1", 
    api_key="ollama",
    temperature=0.1,
)
llm_strict= ChatOpenAI(
    model="my-qwen",   # 모델명 (Qwen3.6:35B)
    base_url="http://localhost:11434/v1", 
    api_key="ollama",
    temperature=0,
)"""
llm_agent = make_chat_llm(temperature=0.1) 
llm_strict = make_chat_llm(temperature=0) 

tools = [search_files, read_file_range]
tools_by_name = {tool.name: tool for tool in tools}

# ==========================================
# [Node 1] Phase 1: Explorer
# ==========================================
def node_phase1_explorer(state: SecurityState) -> dict:
    scan_tool = state["scan_tool"]
    vuln_data_str = json.dumps(state["vuln_data"], indent=2)
    
    print(f"\n" + "="*50)
    print(f"[Phase 1: Explorer] Started for {scan_tool}")
    print(f"="*50)

    # 1. 피드백 주입 (Loop-back)
    feedback_context = ""
    logic_val = state.get("logic_validation")

    if state.get("loop_count", 0) > 0 and logic_val and not logic_val.is_valid:
        feedback = logic_val.reason
        feedback_context = f"[PREVIOUS ATTEMPT FAILED]\nValidator Feedback: {feedback}\nYou MUST address this in your exploration.\n"
        print(f"[Loop-back] Applying feedback from Validator")

    # 2. 스캐너별 가이드라인
    if scan_tool == "SAST":
        exploration_guideline = """[SAST / Static Analysis Guideline]
You are provided with a specific `file_path` and `line_number`.
1. DO NOT use `search_files` to guess locations.
2. IMMEDIATELY use `read_file_range` on the exact `file_path` around the provided line number (e.g., +/- 30 lines).
3. Identify authentication/authorization decorators, input validation, or type casting near the vulnerable line."""

    elif scan_tool == "CodeQL":
        data_flow = state["vuln_data"].get("data_flow", [])

        if data_flow:
            # 시나리오 A: Data Flow가 존재하는 일반적인 Taint-Tracking 취약점
            exploration_guideline = """[CodeQL / Data Flow Analysis Guideline]
You are provided with the complete `prefetched_code` containing the exact Source-to-Sink data flow paths. The code snippets include explicit line numbers on the left, and the exact lines flagged by the scanner are marked with `// <--- [CodeQL TARGET LINE]`.

1. [MANDATORY TARGET DECLARATION (DO THIS FIRST)]: Before executing any tool calls, locate the Target Line in the [Data Flow SOURCE] in the `prefetched_code`. You MUST output a brief text explicitly stating the exact original tainted variable initialized or passed at this line.
2. [VARIABLE LOCK-IN]: Once you declare the target variable, you MUST trace how this exact variable's name changes through the marked lines. You are STRICTLY FORBIDDEN from shifting your focus to other, unrelated variables that happen to be nearby.
3. [AUTHORIZED TOOL USE]: DO NOT use `search_files` or `read_file_range` on the files already provided in the `data_flow` context. ONLY use tools to look up external function definitions or constants that are missing from the snippets.
4. [CRITICAL: BUSINESS LOGIC & CONTROL FLOW VALIDATION]: When tracing your locked-in variable to the final Sink, you are STRICTLY FORBIDDEN from skipping intermediate lines. You MUST perform a chronological, line-by-line inspection for Control Flow Defenses. Specifically, you MUST actively look for and report:
   - [State Matching]: Is the tainted variable validated against a strict allowlist, existing database records, or API responses?
   - [Early Returns / Halts]: Is there an explicit conditional block that halts or redirects execution BEFORE reaching the sink if the validation fails?"""
        else:
            # 시나리오 B: Data Flow가 비어있는 환경설정(Configuration) 및 구조 검사 취약점
            exploration_guideline = """[CodeQL / Configuration & AST Check Guideline]
This CodeQL alert does NOT contain a data flow path. It is a configuration or structural vulnerability check.
You are provided with a specific `file_path` and `line_number`.

1. [INITIAL INSPECTION]: IMMEDIATELY use `read_file_range` on the provided `file_path` around the `line_number`.
2. [DELEGATION TRACING]: You MUST actively scan the broader structural context of the file to understand how the system is actually secured. Specifically, you must look for the following delegation patterns:
   - Dependencies injected via constructors or class fields (e.g., a custom validator or provider).
   - Custom middleware, filters, or interceptors explicitly registered in the execution chain or routing logic.
   - Helper classes or custom modules imported and invoked within the configuration block.
   If the code delegates authentication, authorization, or any security handling to such a custom component, you MUST trace it.
3. [CRITICAL: EXACT KEYWORD ONLY]: Your `keyword` for `search_files` MUST be a specific custom class, function, or module name that is EXPLICITLY INSTANTIATED or IMPORTED in the code you just read. You are STRICTLY PROHIBITED from searche with for generic security concepts (e.g., searching for "cors", "https", "CsrfToken", "JSESSIONID" or "logger") as the 'keyword'.
4. [VERIFY IMPLEMENTATION]: Use `read_file_range` to inspect the actual definition/implementation of the delegated component. Gather factual evidence of how it operates internally to completely prove or disprove the vulnerability.
5. [EXPLORATION BOUNDARY]: Your ONLY job is to verify the direct security configuration and its immediate delegated components. DO NOT trace further into unrelated business logic. Stop when you have read the delegated component.
"""

    elif scan_tool == "Trivy":
        exploration_guideline = """[Trivy / Dependency & OS Scan Guideline]
You are dealing with a vulnerable package, library, or OS component.
1. DO NOT search the application source code (.java, .js, etc.) for the CVE.
2. Focus on infrastructure files. Use `read_file_range` or `search_files` on configuration files like `pom.xml`, `application.yml`, `Dockerfile`, or `nginx.conf` if needed.
3. Determine if the vulnerable package's attack vector is actually exposed to untrusted input, or if secure framework defaults neutralize the threat."""

    elif scan_tool == "ZAP":
        exploration_guideline = """[ZAP / Dynamic Web Scan Guideline]
You only have a target URL, HTTP method, and potentially reflected payloads or missing headers.
1. Extract unique keywords from the URL path (e.g., '/api/users/login' -> 'login').
2. Use `search_files` to locate the backend routing layer or Controller matching the URL.
3. Use `read_file_range` to inspect the identified file.
4. Check how the server handles the request, if there are missing security configurations, or if the input is reflected without escaping."""

    elif scan_tool == "Schemathesis":
        exploration_guideline = """[Schemathesis / API Fuzzing Guideline]
You have an API endpoint that failed edge-case testing (e.g., 500 internal server errors, OpenAPI schema violations).
1. Use `search_files` with the endpoint path to find the exact API Controller or Handler.
2. Use `read_file_range` to inspect the parameter validation logic and error handling (e.g., try-catch blocks) in that file.
3. Identify why the application crashed or bypassed business logic when receiving malformed/fuzzed payloads."""

    else:
        exploration_guideline = """[General Exploration Guideline]
Use `search_files` to find relevant files based on the vulnerability data, then use `read_file_range` to inspect the code and extract security facts."""

    system_prompt = f"""You are an elite DevSecOps Explorer Agent.
Your ONLY job is to use tools to investigate the codebase and gather factual evidence.

[CRITICAL PROHIBITION]
1. DO NOT let the scanner's narrative bias your tool motivation. The scanner's descriptions are subjective claims, NOT facts.
2. Do NOT evaluate the risk. Your ONLY job is to state the objective technical facts.
3. Do NOT call `read_file_range` for a line range that is a SUBSET of or ENTIRELY CONTAINED within a range you have already read or call `search_files` with the same keyword in a directory you've already searched.
4. DO NOT WRITE A SUMMARY OR FINAL REPORT. When you are finished exploring, output ONLY a brief sentence explaining why no further tool calls are needed. Another dedicated agent will write the final summary.
[Directory Tree Context]
{state.get('project_tree', 'No tree provided.')}

{exploration_guideline}
{feedback_context}
"""

    # 3. Native Tool Calling 바인딩
    llm_with_tools = llm_agent.bind_tools(tools)
    
    # 대화 기록(Messages) 초기화
    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"Vulnerability Data:\n{vuln_data_str}")
    ]

    print(f"\n [Tool Calling History]")
    
    # 4. 수동 도구 호출 루프
    max_iterations = 30
    hit_max_iterations = False
    auto_audit_trail = []
    code_cache = {}
    explorer_final_thought = "No explicit final thought provided."

    for iteration in range(1, max_iterations + 1):
        # LLM에게 현재까지의 대화 기록을 주고 판단을 요구
        ai_msg = llm_with_tools.invoke(messages)
        messages.append(ai_msg)
        
        # LLM이 도구 호출(Tool Calls)을 하지 않았다면 (탐색 완료) 루프 종료
        if not ai_msg.tool_calls:
            if ai_msg.content:
                explorer_final_thought = ai_msg.content.strip()
            print(f" Exploration finished by AI on iteration {iteration}.")
            print(f"  End reason     : {explorer_final_thought}")
            break
            
        # 도구 호출을 요구했다면, 파이썬이 대신 도구를 실행하고 결과를 넘겨줌
        for tool_call in ai_msg.tool_calls:
            tool_name = tool_call["name"]
            tool_args = tool_call["args"]

            agent_motivation = tool_args.get("motivation", f"Iteration {iteration}: General Exploration")

            selected_tool = tools_by_name[tool_name]
            tool_result = selected_tool.invoke(tool_args)

            # 2. 결과 처리 및 캐싱, Audit Trail 기록
            if tool_name == "read_file_range":
                file_path = tool_args.get('file_path', 'Unknown')
                start_line = tool_args.get('start_line')
                end_line = tool_args.get('end_line')
                
                auto_audit_trail.append(AuditTrail(
                    file_path=file_path,
                    read_lines=f"lines {start_line}-{end_line}",
                    reason_for_reading=f"[Iter {iteration}] {agent_motivation}"
                ))

                cache_key = f"{file_path}:{start_line}-{end_line}"
                code_cache[cache_key] = str(tool_result)

                print(f"  [{iteration}] Tool Used  : {tool_name}     Input  : {file_path}, {start_line} - {end_line}")

            elif tool_name == "search_files":
                auto_audit_trail.append(AuditTrail(
                    keyword=tool_args.get("keyword", ""),
                    root_dir=tool_args.get("root_dir", "."),
                    reason_for_reading=f"[Iter {iteration}] {agent_motivation}"
                ))
                print(f"  [{iteration}] Tool Used  : {tool_name}     Input  : {tool_args.get('keyword')}, {tool_args.get('root_dir')}")

            print(f"      reason     : {agent_motivation}")
            
            # 3. 도구 실행 결과를 ToolMessage로 감싸서 대화 기록에 추가
            messages.append(ToolMessage(
                tool_call_id=tool_call["id"], 
                content=str(tool_result), 
                name=tool_name
            ))
            
        if iteration == max_iterations:
            print(f" Max iterations ({max_iterations}) reached. Forcing stop.")
            hit_max_iterations = True

    lightweight_context = json.dumps([a.model_dump() for a in auto_audit_trail], indent=2)

    raw_code_context = ""
    if code_cache:
        raw_code_context = "\n[Reference: Raw Code Snippets Read During Exploration]\n"
        for key, code_snippet in code_cache.items():
            raw_code_context += f"{code_snippet}\n\n"
    
    summary_prompt = f"""Exploration is complete. Based ONLY on the following tool execution history and accumulated facts, write a detailed and strictly objective technical summary of the findings.
    
    [Vulnerability Target & Pre-fetched Code]
    {vuln_data_str}

    [Explorer Agent's Final Thought / Reason for Stopping]
    {explorer_final_thought}
    
    [Agent Execution History & Code Snippets]
    {lightweight_context}
    {raw_code_context}

    [Strict Reporting Constraints - CRITICAL]
    1. OBJECTIVITY ONLY: State ONLY what the code does, what variables are traced, and what functions are called. 
    2. NO FINAL JUDGMENT: Do NOT evaluate the risk, do NOT conclude whether this is a False Positive or True Positive, and do NOT suggest remediations. Leave the judgment to the Triage phase.
    3. NO BIASED LANGUAGE: Strictly AVOID loaded terms like "safe", "secure", "mitigated", "exploitable", or "vulnerable". 
    4. FACTUAL TRACE: Clearly document the exact execution path, line numbers, and specific variables involved from Source to Sink using the raw code provided.
    """

    final_summary_msg = llm_strict.invoke([
        SystemMessage(content="You are a technical report generator. Summarize the facts precisely without hallucination."),
        HumanMessage(content=summary_prompt)
    ])

    agent_summary = final_summary_msg.content.strip()
        
    print(f"\n[Agent Raw Summary]\n{agent_summary[:5000]}...")
    
    investigation = InvestigationResult(
        investigated_context=agent_summary, 
        audit_trail=auto_audit_trail,
        raw_code_context=raw_code_context
    )
    
    vuln_data = state["vuln_data"]
    prefetched_code = vuln_data.get("prefetched_code")
    if prefetched_code:
        print("\n[Prefetched Code Snippets]")
        print("-" * 50)
        print(prefetched_code)
        print("-" * 50 + "\n")
    print(f"\n[Final Extracted JSON (InvestigationResult)]")
    print(json.dumps({"End Reason": explorer_final_thought}, indent=2))
    print(investigation.model_dump_json(indent=2))
    print("="*50 + "\n")

    return {"investigation": investigation}

# ==========================================
# [Node 2] Phase 2: Triage (오탐 판별기)
# ==========================================
def node_phase2_triage(state: SecurityState) -> dict:
    logic_val = state.get("logic_validation")
    feedback_context = ""

    if state.get("loop_count", 0) > 0 and logic_val and not logic_val.is_valid and logic_val.target_retry_node =="Phase_2" :
        feedback = logic_val.reason
        feedback_context = f"\n\n[PREVIOUS ATTEMPT FAILED]\nLogic Validator Feedback: {feedback}\nYou MUST correct your logical reasoning based on this feedback."
        print(f"  [Loop-back] Applying feedback to Triage logic")

    sys_msg = SystemMessage(
        content=f"You are a skeptical security triager. Operate on a 'Zero Trust' principle regarding the scanner. Base your judgment SOLELY on the extracted facts and audit trail from Phase 1.{feedback_context}"
    )
    
    scan_tool = state.get("scan_tool", "Unknown")

    # 1. 스캐너별 정밀 오탐(FP) 판별 가이드라인
    if scan_tool == "SAST":
        triage_guideline = """[SAST Triage Guidelines]
1. Dead Code / Test Files: If the vulnerability resides in unreachable code or test directories, it is a False Positive.
2. Trusted Input: If the "source" of the data is purely internal, hardcoded, or from a strictly trusted database, it is a False Positive.
3. Unrecognized Sanitization & Validation: If Phase 1 found custom sanitization OR strict control-flow validation (e.g., allowlist checks, type casting, execution halts on invalid input) applied to the EXACT variable before the sink, it is a False Positive."""

    elif scan_tool == "CodeQL":
        triage_guideline = """[CodeQL / Data Flow Triage Guidelines]
1. Sanitization: If the audit trail proves the data flow is broken by explicit sanitization or encoding on the EXACT tainted variable before the sink, classify as a False Positive.
2. Business Logic Validation: If the tainted variable is validated against a strict allowlist and the execution is explicitly halted/returned before reaching the sink, the attack chain is broken. Classify as a False Positive.
3. Trusted Source: If the starting point of the data flow is not actually user-controllable, it is a False Positive."""

    elif scan_tool == "Trivy":
        triage_guideline = """[Trivy / SCA Triage Guidelines]
1. Architectural Norms: Standard internal proxy header forwarding is a False Positive. HOWEVER, if the application serves Public Internet traffic, passing raw unvalidated headers WITHOUT an explicit allowlist or regex validation at the edge proxy is a True Positive.
2. The "Framework Shield" Rule: If the higher-level architecture completely terminates, sanitizes, or blocks the malicious payload before it reaches the vulnerable component, it is a False Positive. 
3. Reachability: If the vulnerable library/package is merely present in the manifest but NEVER loaded, executed, or exposed to external input, it is a False Positive.
4. Note: Network isolation or internal environment status do not make a technically reachable vulnerability a False Positive."""

    elif scan_tool == "ZAP":
        triage_guideline = """[ZAP / DAST Triage Guidelines]
1. Safe Error Handling: If ZAP flagged a 500 error but the backend safely caught the exception without leaking stack traces or sensitive data, it is a False Positive.
2. Safe Reflection: If ZAP flagged reflected input, but Phase 1 confirms the backend logic applies proper Context-Aware Encoding (e.g., HTML entity encoding) before returning the response, it is a False Positive.
3. Missing Headers Context: Missing security headers (like CSRF or X-Frame-Options) on stateless, JWT-based REST APIs (not serving HTML) are False Positives."""

    elif scan_tool == "Schemathesis":
        triage_guideline = """[Schemathesis / API Fuzzing Triage Guidelines]
1. Expected Client Errors: 4xx HTTP responses (e.g., 400 Bad Request, 422 Unprocessable Entity) generated by framework validation logic are expected behaviors and classify as False Positives.
2. Safe Failures: 500 errors are False Positives ONLY IF they are caught globally and return a generic error message without crashing the service (no DoS) and without leaking stack traces.
3. Business Logic Bypass: If the fuzzed payload bypasses authorization or manipulates state unexpectedly, it is a True Positive."""

    else:
        triage_guideline = """[General Triage Guidelines]
1. Assume False Positive UNLESS the investigated context shows a clear, exploitable path.
2. If the vulnerability is technically mitigated by explicit code logic or infrastructure, it is a False Positive."""

    # 2. 최종 프롬프트 조립
    prompt = f"""Determine if this vulnerability is a False Positive.
- Scan Tool: {scan_tool}
- System Context: {state['system_context']}
- Vuln Data: {state['vuln_data']}
- Explored Raw Code: {state.get('investigation').raw_code_context}
- Investigated Facts: {state['investigation'].investigated_context} 

{triage_guideline}

[Universal Triage Rules]
1. Assume False Positive UNLESS the investigated context shows a clear, exploitable path based on the guidelines above.
2. Rely ONLY on the explicit facts proven by the investigated facts and the provided System Context. You are STRICTLY PROHIBITED from assuming mitigations based on tech stack names or framework defaults. Do not presuppose absent WAFs or missing proxies.
3. [CRITICAL] DO NOT dismiss a vulnerability solely based on subjective opinions about performance, algorithmic complexity, or exploit likelihood.
4. Assess Confidence (0-100) based on the clarity of the evidence.
"""

    structured_llm = llm_strict.with_structured_output(TriageResult)
    triage = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])

    print(f"\n[Phase 2: Triage Log]")
    print(triage.model_dump_json(indent=2))

    return {"triage": triage}

# ==========================================
# [Node 3] Phase 3: Logic Validator (사실/논리 검증 에이전트)
# ==========================================
def node_phase3_logic_validator(state: SecurityState) -> dict:
    sys_msg = SystemMessage(
        content="You are the strict Logic Validator. Your job is to rigorously ensure Phase 1 explored the correct files based on the specific scanner type, and the conclusion of Phase 2 (Triage) is logically sound without hallucination."
    )

    scan_tool = state.get("scan_tool", "Unknown")

    # 1. 스캐너별 검증 룰 분기 처리
    if scan_tool == "SAST":
        validation_guideline = """[SAST Validation Rule]
- [Syntax Check]: Did Phase 1 explicitly read the exact `line_number` reported in the Vuln Data? If the exact line was not read via `read_file_range`, it is INVALID.
- [Semantic Check]: If Phase 1 claims a sanitization or mitigation exists, verify it applies to the EXACT variable or function call flagged at the `line_number`. If Phase 1 confused variables and the sanitization applies to a different variable, it is INVALID."""

    elif scan_tool == "CodeQL":
        validation_guideline = """[CodeQL / Data Flow Validation Rule]
- [Syntax Check]: Verify that Phase 1's investigated facts are based on either the `prefetched_code` provided in the Vuln Data OR explicit tool usage in the Audit Trail. If the core vulnerable lines were pre-fetched, Phase 1 is NOT required to have an Audit Trail for them.
- [Semantic Check]: Trace the exact variable name from the Source. If Phase 1 claims the flow is sanitized, you MUST check if the sanitization function (e.g., `esc()`) wraps the EXACT original variable, AND that Phase 1 actively searched for and read the definition of that sanitization function using tools."""

    elif scan_tool == "Trivy":
        validation_guideline = """[Trivy / SCA Validation Rule]
- [Syntax Check]: Did Phase 1 investigate the structural context (e.g., pom.xml, Dockerfile, application.yml) to confirm if the vulnerable package is actually reachable or exposed? If Triage claims "Framework Shield" without Phase 1 reading the relevant config files, it is INVALID.
- [Semantic Check]: If Phase 1 claims a network constraint or framework default mitigates the issue, verify that this specific defense actually covers the vulnerable package's explicit execution path or exposed port, rather than being a generic, unrelated system configuration."""

    elif scan_tool == "ZAP":
        validation_guideline = """[ZAP / DAST Validation Rule]
- [Syntax Check]: Did Phase 1 successfully locate and read the backend routing layer/Controller that matches the attacked URL? If Phase 1 failed to map the URL to a backend file and just guessed the logic, it is INVALID.
- [Semantic Check]: Verify that Phase 1 explicitly inspected the handling of the EXACT payload or vulnerable parameter flagged by ZAP. If Phase 1 analyzed a different parameter or a safe logic branch within the same Controller, it is INVALID."""

    elif scan_tool == "Schemathesis":
        validation_guideline = """[Schemathesis / API Fuzzing Validation Rule]
- [Syntax Check]: Did Phase 1 locate the exact API endpoint handler and inspect its parameter validation or try-catch error handling logic? If the audit trail does not show inspection of the endpoint's error handling, it is INVALID.
- [Semantic Check]: Verify that the inspected error handling or validation directly addresses the specific schema violation or edge-case payload reported. If Phase 1 relies on generic exception catching that still allows the business logic bypass or crash to occur, it is INVALID."""

    else:
        validation_guideline = """[General Validation Rule]
- Did Phase 1 actually read the relevant files matching the vulnerability data?
- If the audit trail lacks evidence of reading the core vulnerability location, it is INVALID."""

    # 2. 최종 프롬프트 조립
    prompt = f"""Review the pipeline execution:
- Scan Tool: {scan_tool}
- Scanner's Original Vuln Data: {json.dumps(state.get('vuln_data', {}))}
- Audit Trail (Tools Executed): {json.dumps([a.model_dump() for a in state['investigation'].audit_trail], indent=2)}
- Explored Raw Code: {state.get('investigation').raw_code_context}
- Investigated Facts: {state['investigation'].investigated_context}
- Triage Result: {state['triage'].model_dump_json()}

{validation_guideline}

[General Logic Rules]
1. Set is_valid True ONLY IF the Triage reason is logical and it directly relys on the evidence from the Audit Trail and the Investigated Facts.
2. You MUST write a detailed logical `reason` for your judgment BEFORE setting the `is_valid` boolean.
3. [CRITICAL FORMATTING]: For the `reason` field, write a plain text paragraph consisting of at least 3 sentences. DO NOT use markdown headers (like "###" or "QA Validation Report"), bullet points, or line breaks inside the `reason` string, as it will break the JSON parser.
4. If ANY of the scanner-specific rules fail, set `is_valid` to False.
5. [Routing Rule on Failure]: If `is_valid` is False, you MUST set `target_retry_node` to "Phase_1" (if evidence/tool usage is lacking/wrong) or "Phase_2" (if Phase 1 facts are correct but Phase 2 made a logical error/hallucinated).
"""

    structured_llm = llm_strict.with_structured_output(LogicValidationResult)
    validation = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    print(f"\n[Phase 3: Logic Validator Log]")
    print(f" - Valid: {validation.is_valid}")
    print(f" - Reason: {validation.reason}")
    if not validation.is_valid:
        print(f" - Target Retry Node: {validation.target_retry_node}")

    current_loop = state.get("loop_count", 0)
    return {
        "logic_validation": validation,
        "loop_count": current_loop + 1
    }

# ==========================================
# [Node 4] Phase 4: Root Cause And Remediation
# ==========================================
def node_phase4_root_cause(state: SecurityState) -> dict:
    if state["triage"].is_false_positive:
        return {"root_cause": None}

    sys_msg = SystemMessage(content="You are a senior security architect. Identify the root cause of the vulnerability and provide an actionable remediation guide.")
    
    # 1. 피드백 주입 (Loop-back)
    feedback_context = ""
    remediation_val = state.get("remediation_validation")
    
    if state.get("remediation_loop_count", 0) > 0 and remediation_val and not remediation_val.is_valid:
        feedback = remediation_val.feedback_for_correction
        prev_rc = state.get("root_cause")
        prev_rc_json = prev_rc.model_dump_json(indent=2) if prev_rc else "N/A"
        
        feedback_context = f"""
[PREVIOUS REMEDIATION FAILED VALIDATION]
- Previous Attempt: {prev_rc_json}
- Validator Feedback: {feedback}

You MUST correct your remediation guide based exactly on this feedback."""
        print(f"  [Loop-back] Applying feedback from Remediation Validator to Phase 4")

    prompt = f"""Analyze the root cause and provide a fix.
- Scan Tool: {state['scan_tool']}
- Scanner's Original Vuln Data: {state['vuln_data']}
- Explored Raw Code: {state['investigation'].raw_code_context}
- Investigated Facts: {state['investigation'].investigated_context} 
{feedback_context}

Identify exactly WHICH line/logic is flawed and write a concise remediation step."""
    
    structured_llm = llm_strict.with_structured_output(RootCauseAnalysis)
    rc_analysis = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])

    print(f"\n[Phase 4: Root Cause And Remediation Log]")
    print(rc_analysis.model_dump_json(indent=2))

    return {"root_cause": rc_analysis}

# ==========================================
# [Node 5] Phase 5: Remediation Validator (해결책/코드 검증 에이전트)
# ==========================================
def node_phase5_remediation_validator(state: SecurityState) -> dict:
    sys_msg = SystemMessage(
        content="You are the Code & Remediation Validator. Your job is to rigorously review the Root Cause and Remediation Guide generated by Phase 4. Phase 1, 2, and 3 have already confirmed this is a True Positive, so DO NOT question the vulnerability's existence."
    )
    raw_code = state.get('investigation').raw_code_context if state.get('investigation') else 'N/A'
    scan_tool = state.get("scan_tool", "Unknown")
    rc_obj = state.get("root_cause")
    rc_json = rc_obj.model_dump_json(indent=2) if rc_obj else "N/A"
    
    prompt = f"""Review the proposed Root Cause and Remediation Guide:
- Scan Tool: {scan_tool}
- Explored Raw Code: {raw_code}
- Investigated Facts (Context): {state['investigation'].investigated_context}
- Proposed Root Cause & Remediation: {rc_json}

[Code & Remediation Validation Rules]
1. [Context Alignment]: Does the remediation target the EXACT lines, variables, and files identified in the Investigated Facts? If Phase 4 hallucinates non-existent files, functions, or modifies unrelated logic, it is INVALID.
2. [Code Correctness]: Does the proposed code snippet actually mitigate the vulnerability? (e.g., proper encoding/escaping, strict allowlist validation). If the fix introduces syntax errors or incomplete logic, it is INVALID.
3. [Actionability]: Is the explanation clear, specific, and actionable for a developer?

[General Logic Rules]
1. DO NOT evaluate whether this is a True Positive or False Positive. Assume the vulnerability is confirmed. Focus ONLY on the quality of the fix.
2. [CRITICAL FORMATTING]: For the `reason` field, write a plain text paragraph consisting of at least 3 sentences. DO NOT use markdown headers (like "###"), bullet points, or line breaks inside the `reason` string, as it will break the JSON parser.
3. If `is_valid` is False, provide a highly specific `feedback_for_correction` instructing Phase 4 exactly what to change in the code or root cause. If True, leave it as 'N/A'.
"""
    
    structured_llm = llm_strict.with_structured_output(RemediationValidationResult)
    validation = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])
    
    print(f"\n[Phase 5: Code Validator Log]")
    print(f" - Valid: {validation.is_valid}")
    print(f" - Reason: {validation.reason}")
    if not validation.is_valid:
        print(f" - Feedback: {validation.feedback_for_correction}")

    current_remediation_loop = state.get("remediation_loop_count", 0)
    return {
        "remediation_validation": validation,
        "remediation_loop_count": current_remediation_loop + 1
    }

# ==========================================
# [Node 6] Phase 6: Risk Assessor
# ==========================================
def node_phase6_risk_assessor(state: SecurityState) -> dict:
    if state["triage"].is_false_positive:
        return {"risk_assessment": None}

    sys_msg = SystemMessage(content="You assign business risk severity to True Positive vulnerabilities based on system context and exposure.")
    prompt = f"""Evaluate final business risk (Critical/High/Medium/Low/Info).
- System Context: {state['system_context']}
- Extracted Facts (Mitigations): {state['investigation'].investigated_context}
- Root Cause: {state['root_cause'].root_cause}
Adjust severity down if it's an internal/dev environment. Adjust up if it affects authentication/payment."""
    
    structured_llm = llm_strict.with_structured_output(RiskAssessment)
    risk = structured_llm.invoke([sys_msg, HumanMessage(content=prompt)])

    print(f"\n[Phase 6: Assessor Log]")
    print(risk.model_dump_json(indent=2))

    return {"risk_assessment": risk}

# ==========================================
# [Node 7] Phase 7: Markdown Reporter
# ==========================================
def node_phase7_reporter(state: SecurityState) -> dict:
    triage = state["triage"]
    scan_tool = state.get("scan_tool", "Unknown")
    vuln_data = state.get("vuln_data", {})

    logic_val = state.get("logic_validation")
    remediation_val = state.get("remediation_validation")
    
    # 루프 제한 초과로 인해 검증을 통과하지 못한 채 도달했는지 확인
    logic_failed = logic_val and not logic_val.is_valid
    remediation_failed = remediation_val and not remediation_val.is_valid
    
    # Phase 1에서 수집한 텍스트 요약본
    investigated_context = state.get("investigation").investigated_context if state.get("investigation") else "No context available."

    # 1. 스캐너별 동적 Target 및 Vuln Name 설정 (CodeQL, Schemathesis 포함)
    target = "Unknown Target"
    vuln_name = "Unknown Vuln"

    if scan_tool in ["SAST", "CodeQL"]:
        target = vuln_data.get("file_path", "Unknown Target")
        vuln_name = vuln_data.get("rule_id", "Unknown Vuln")
        
    elif scan_tool == "Trivy":
        pkg_name = vuln_data.get("package_name", "Unknown Pkg")
        target = f"{vuln_data.get('target', 'Unknown')} ({pkg_name})"
        vuln_name = vuln_data.get("cve_id", "Unknown CVE")
        
    elif scan_tool in ["DAST", "ZAP", "Schemathesis"]:
        affected = vuln_data.get("affected_targets", [])
        # 여러 URL이 있을 경우 첫 번째 URL 외 N건으로 표기
        if affected:
            target = affected[0].get("url", "Unknown URL")
            if len(affected) > 1:
                target += f" (and {len(affected)-1} more)"
        vuln_name = vuln_data.get("alert_name", vuln_data.get("rule_id", "Unknown Alert"))

    # 2. System Message (포맷팅 강제)
    sys_msg = SystemMessage(
        content="You are a technical writer generating concise Markdown security reports. Output ONLY the raw Markdown text. Do NOT include greetings, conversational padding, or markdown code blocks (```markdown)."
    )
    
    # 3. 오탐 / 정탐 분기 및 프롬프트 조립
    if triage.is_false_positive:
        # 오탐(False Positive)일 경우
        prompt = f"""Generate a short Markdown report for a False Positive finding.
- Target: {target}
- Rule/Vuln: {vuln_name}
- Reason for False Positive: {triage.reason}
- Confidence: {triage.confidence_score}%

Format Requirements:
You MUST strictly follow this exact markdown structure below without omitting any fields:

### 🛡️ [False Positive] {vuln_name} (Confidence: {triage.confidence_score}%)

**Target:** {target}  
**Reason:** <Refine and false for here positive reason the write>
"""
    else:
        # 정탐(True Positive)일 경우 (Risk, Root Cause, Investigation 병합)
        risk = state["risk_assessment"]
        rc = state["root_cause"]
        
        prompt = f"""Generate a concise Markdown report for a True Positive vulnerability.
- Target: {target}
- Rule/Vuln: {vuln_name}
- Final Risk: {risk.final_risk}
- Impact Reason: {risk.impact_reason}
- Root Cause: {rc.root_cause}
- Remediation: {rc.remediation_guide}
- Investigated Context: {investigated_context}
- Confidence: {triage.confidence_score}%

Format Requirements:
You MUST strictly follow this exact markdown structure below without omitting any fields:

### 🚨 [True Positive - {risk.final_risk}] {vuln_name} (Confidence: {triage.confidence_score}%)

- **Target:** {target}
- **Context:** <Summarize and cause context investigated root the>
- **Impact:** <State and business impact reason risk the>
- **Suggested Action:** <Provide a actionable based concise, guide on remediation step the>
"""

    # 4. LLM 호출 (리포트는 순수 문자열이므로 llm_strict.invoke 사용)
    response = llm_strict.invoke([sys_msg, HumanMessage(content=prompt)])
    generated_report = response.content.strip()

    # 5. 서킷 브레이커 경고 배너 조립 (Python 레벨에서 강제 삽입)
    warning_banner = ""
    
    if logic_failed or remediation_failed:
        warning_banner += "> ⚠️ **[SYSTEM WARNING: AI VALIDATION FAILED]**\n"
        warning_banner += "> *The AI agent reached the maximum retry limit (Circuit Breaker triggered). The information below did not pass the automated quality assurance and may contain logical errors, hallucinations, or incorrect remediation code.*\n>\n"
        
        if logic_failed:
            warning_banner += f"> - **Logic Error Details:** {logic_val.reason}\n"
        if remediation_failed:
            warning_banner += f"> - **Remediation Error Details:** {remediation_val.reason}\n"
            
        warning_banner += "\n---\n\n"

    # 6. 배너와 LLM 리포트 결합
    final_report_md = warning_banner + generated_report
    
    # 7. 콘솔 로깅
    print(f"\n[Phase 7: Reporter Log]")
    if logic_failed or remediation_failed:
        print(" - ⚠️ Circuit Breaker Warning added to report.")
    print(" - Markdown report successfully generated.")

    return {"final_report_md": final_report_md}