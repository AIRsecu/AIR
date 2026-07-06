from typing import TypedDict, Dict, Any, List, Optional
from pydantic import BaseModel, Field

# ==========================================
# 1. Phase 1 (Extractor) Output Schema
# ==========================================
class ExtractedFacts(BaseModel):
    decorators: List[str] = Field(
        default_factory=list, 
        description="List of authentication, authorization, or routing decorators applied to the target function/class."
    )
    sanitization_logic: List[str] = Field(
        default_factory=list, 
        description="List of security defense mechanisms found, such as type casting (e.g., int()), input validation, or escaping logic."
    )
    data_models: List[str] = Field(
        default_factory=list, 
        description="Names of sensitive database tables or variables handled within the logic."
    )
    return_type: str = Field(
        default="Unknown", 
        description="The final output format of the function (e.g., HTML template render, JSON response, HTTP status code)."
    )
    need_more_context: bool = Field(
        default=False, 
        description="Set to True ONLY IF the provided code snippet is too heavily truncated to extract meaningful facts."
    )

# ==========================================
# 2. Phase 2 (Triage) Output Schema
# ==========================================
class TriageResult(BaseModel):
    is_false_positive: bool = Field(
        description="True if the vulnerability is deemed a false positive (safe) based on the extracted facts and mitigations. False if it is a true positive."
    )
    fp_reason: str = Field(
        description="Clear and logical explanation for why this is considered a false positive or true positive."
    )

# ==========================================
# 3. Phase 3 (Assessor) Output Schema
# ==========================================
class RiskAssessment(BaseModel):
    final_risk: str = Field(
        description="The final assessed risk severity. MUST be one of: 'Critical', 'High', 'Medium', 'Low', 'Info'."
    )
    impact_reason: str = Field(
        description="A concise and logical explanation of how the business context, file path, and exposure level influenced the final risk rating."
    )

# ==========================================
# 4. LangGraph Global State
# ==========================================
class SecurityState(TypedDict):
    scan_tool: str                  
    system_context: str             
    vuln_data: Dict[str, Any]       
    
    extracted_facts: Any            # ExtractedFacts (Phase 1)
    triage_result: Any              # TriageResult (Phase 2)
    risk_assessment: Optional[Any]  # RiskAssessment (Phase 3, 오탐일 경우 None)
    final_report_md: str            # Phase 4 결과물 (마크다운 텍스트)

