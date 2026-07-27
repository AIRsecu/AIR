from typing import TypedDict, Dict, Any, List, Optional, Literal
from pydantic import BaseModel, Field

# ==========================================
# 1. Phase 1 (Explorer) Output Schema
# ==========================================
class AuditTrail(BaseModel):
    # --- read_file_range 도구용 필드 ---
    file_path: Optional[str] = Field(default=None, description="The exact file path read by the agent.")
    read_lines: Optional[str] = Field(default=None, description="The line range read (e.g., 'lines 40-100').")
    
    # --- search_files 도구용 필드 ---
    keyword: Optional[str] = Field(default=None, description="The keyword searched.")
    root_dir: Optional[str] = Field(default=None, description="The directory searched.")
    
    # --- 공통 필드 ---
    reason_for_reading: str = Field(description="Why this action was performed.")

class InvestigationResult(BaseModel):
    investigated_context: str = Field(description="The full, detailed text summary of the exploration, including data flows, configurations, and found code logic.")
    audit_trail: List[AuditTrail] = Field(default_factory=list, description="List of files and lines actually read using tools.")
    raw_code_context: Optional[str] = Field(default="", description="Raw code snippets collected during Phase 1 exploration.")


# ==========================================
# 2. Phase 2 (Triage) Output Schema
# ==========================================
class TriageResult(BaseModel):
    is_false_positive: bool = Field(description="True if the vulnerability is deemed a false positive (safe). False if it is a true positive.")
    reason: str = Field(description="Clear and logical explanation for why this is considered a false positive or true positive.")
    confidence_score: int = Field(description="Confidence level of your decision, from 0 to 100.")


# ==========================================
# 3. Phase 3 (Logic Validator) Output Schema - 1차 검증
# ==========================================
class LogicValidationResult(BaseModel):
    is_valid: bool = Field(..., description="True if Phase 1 and Phase 2 logic is sound and fact-based.")
    reason: str = Field(..., description="Detailed explanation (Plain text, min 3 sentences, no markdown).")
    target_retry_node: Optional[Literal["Phase_1", "Phase_2"]] = Field(
        default=None, 
        description="If is_valid is False, specify 'Phase_1' (evidence error) or 'Phase_2' (logic error)."
    )


# ==========================================
# 4. Phase 4 (Root Cause) Output Schema
# ==========================================
class RootCauseAnalysis(BaseModel):
    root_cause: str = Field(description="Technical root cause of the vulnerability based on the investigated code.")
    remediation_guide: str = Field(description="Actionable steps or code snippets to fix the issue.")


# ==========================================
# 5. Phase 5 (Remediation Validator) Output Schema - 2차 검증
# ==========================================
class RemediationValidationResult(BaseModel):
    is_valid: bool = Field(..., description="True if Phase 4's root cause and code fix are correct, secure, and syntax-error free.")
    reason: str = Field(..., description="Detailed explanation (Plain text, min 3 sentences, no markdown).")
    feedback_for_correction: str = Field(default="N/A", description="If is_valid is False, provide specific instructions to Phase 4. If True, output 'N/A'.")


# ==========================================
# 6. Phase 6 (Risk Assessor) Output Schema
# ==========================================
class RiskAssessment(BaseModel):
    final_risk: str = Field(description="The final assessed risk severity. MUST be one of: 'Critical', 'High', 'Medium', 'Low', 'Info'.")
    impact_reason: str = Field(description="A logical explanation of how the business context and exposure level influenced the final risk rating.")


# ==========================================
# 7. LangGraph Global State (TypedDict)
# ==========================================
class SecurityState(TypedDict):
    # --- Input Context ---
    scan_tool: str                  
    system_context: str             # Base OS, Tech Stack, Network (for Phase 2,6)
    project_tree: str               # Directory Tree (for Phase 1)
    vuln_data: Dict[str, Any]       
    
    # --- Phase Outputs ---
    investigation: Optional[InvestigationResult]
    triage: Optional[TriageResult]               
    logic_validation: Optional[LogicValidationResult]   # Output of Phase 3
    root_cause: Optional[RootCauseAnalysis]             # Output of Phase 4
    remediation_validation: Optional[RemediationValidationResult] # Output of Phase 5
    risk_assessment: Optional[RiskAssessment]           # Output of Phase 6
    
    final_report_md: str            # Output of Phase 7
    
    # --- Loop/Retry Control ---
    loop_count: int                 # Logic Validator(Phase 3)에서 실패하여 되돌아간 횟수
    remediation_loop_count: int            # Remediation Validator(Phase 5)에서 실패하여 되돌아간 횟수