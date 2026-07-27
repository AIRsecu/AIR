import os
import yaml
from typing import List, Dict, Any, Optional
from langchain_core.tools import tool
from pydantic import BaseModel, Field

# ==========================================
# 1. Config Loading & Parsing
# ==========================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CONFIG_PATH = os.path.join(BASE_DIR, "agent_config.yaml")

def load_agent_config(config_path: str = DEFAULT_CONFIG_PATH) -> dict:
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)
    except Exception as e:
        print(f"[Warning] Failed to load {config_path}. Using safe fallback limits. Error: {e}")
        return {}

CONFIG = load_agent_config()

# Limits
LIMITS = CONFIG.get("limits", {})
MAX_RESULTS = LIMITS.get("max_results", 5)
MAX_READ_RANGE_LINES = LIMITS.get("max_read_range_lines", 300)

# Flatten Exclude Directories
EXCLUDE_DIRS = set()
for category, dirs in CONFIG.get("exclude_dirs", {}).items():
    EXCLUDE_DIRS.update(dirs)

# Flatten Allowed Extensions
ALLOWED_EXTENSIONS = tuple(
    ext for category, exts in CONFIG.get("allowed_extensions", {}).items() for ext in exts
)

# Other File Rules
EXCLUDE_EXTENSIONS = tuple(CONFIG.get("exclude_extensions", []))
ALLOWED_FILENAMES = set(CONFIG.get("allowed_filenames", []))
EXCLUDE_FILES = set(CONFIG.get("exclude_files", []))
MINIFIED_SUFFIXES = tuple(CONFIG.get("minified_suffixes", []))
OS_JUNK_FILES = set(CONFIG.get("os_junk_files", []))

# Merge specific file exclusions
ALL_EXCLUDED_FILES = EXCLUDE_FILES | OS_JUNK_FILES

# ==========================================
# 2. Tool Input Schemas
# ==========================================
class SearchFilesInput(BaseModel):
    keyword: str = Field(..., description="The keyword to search for (e.g., function name, dangerous API call, or endpoint path like '/api/users').")
    root_dir: Optional[str] = Field(".", description="Optional root directory to limit the search scope (e.g., 'src/main', 'frontend/js').")
    motivation: str = Field(..., description="Explain exactly WHY you are searching for this keyword (e.g., 'To find the definition of the tenantName variable').")

class ReadFileRangeInput(BaseModel):
    file_path: str = Field(..., description="The exact filepath returned by the search_files tool.")
    start_line: int = Field(..., description="Starting line number (1-based, inclusive).")
    end_line: int = Field(..., description="Ending line number (1-based, inclusive). Must be >= start_line. (end_line - start_line) MUST NOT exceed the configured limit (300).")
    motivation: str = Field(..., description="Explain exactly WHY you are reading this specific line range and what security fact you are trying to extract.")

# ==========================================
# 3. LangChain Tools
# ==========================================
@tool("search_files", args_schema=SearchFilesInput)
def search_files(keyword: str, motivation: str, root_dir: str = ".") -> List[Dict[str, Any]]:
    """Search for files containing a specific keyword. Returns matches including the clean filepath, total_lines, file_size_bytes, and the exact line numbers where the keyword was found (matched_lines). ALWAYS use this first to locate files."""
    results = []
    
    try:
        for root, dirs, files in os.walk(root_dir):
            # 1. Directory Filtering (YAML Policy)
            dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
            
            for file in files:
                # 2. File Level Filtering (YAML Policy)
                if file in ALL_EXCLUDED_FILES or file.endswith(MINIFIED_SUFFIXES):
                    continue
                if file.endswith(EXCLUDE_EXTENSIONS):
                    continue
                if not (file.endswith(ALLOWED_EXTENSIONS) or file in ALLOWED_FILENAMES):
                    continue
                    
                file_path = os.path.join(root, file)
                
                # 3. Read and Search
                try:
                    with open(file_path, 'r', encoding=CONFIG.get('encoding', {}).get('default', 'utf-8'), errors='ignore') as f:
                        lines = f.readlines()
                        
                    matched_lines = []
                    for i, line in enumerate(lines):
                        if keyword in line:
                            matched_lines.append(i + 1) # 1-based line number
                            
                    if matched_lines:
                        results.append({
                            "file_path": file_path,
                            "total_lines": len(lines),
                            "file_size_bytes": os.path.getsize(file_path),
                            "matched_lines": matched_lines[:10] # Provide max 10 matches per file to save tokens
                        })
                        
                        # Stop if max_results hit
                        if len(results) >= MAX_RESULTS:
                            return results
                            
                except Exception:
                    # Ignore unreadable files (binary, permission issues, etc.) as per policy
                    continue
                    
    except Exception as e:
        return [{"error": str(e)}]
        
    return results


@tool("read_file_range", args_schema=ReadFileRangeInput)
def read_file_range(file_path: str, start_line: int, end_line: int, motivation: str) -> str:
    """Read a specific line range of a file. You MUST use the 'matched_lines' and 'total_lines' returned by 'search_files' to set 'start_line' and 'end_line' accurately without guessing."""
    if not os.path.exists(file_path):
        return f"[Error] File not found: {file_path}"
        
    if end_line < start_line:
        return "[Error] end_line must be greater than or equal to start_line."
        
    if (end_line - start_line) > MAX_READ_RANGE_LINES:
        return f"[Error] Requested range exceeds the maximum allowed lines ({MAX_READ_RANGE_LINES}). Please narrow your search."
        
    try:
        with open(file_path, 'r', encoding=CONFIG.get('encoding', {}).get('default', 'utf-8'), errors='ignore') as f:
            lines = f.readlines()
            
        # Convert 1-based input to 0-based Python slicing
        start_idx = max(0, start_line - 1)
        end_idx = min(len(lines), end_line)
        
        snippet = "".join(lines[start_idx:end_idx])
        return f"--- Target File: {file_path} (Lines {start_line}-{end_line}) ---\n```\n{snippet}\n```"
        
    except Exception as e:
        return f"[Error] Could not read file: {str(e)}"

def get_project_tree(root_dir: str, max_depth: int = 3) -> str:
    """프로젝트 디렉토리 트리를 텍스트로 추출합니다."""
    IGNORE_DIRS = { 'scripts', 'reports', 'policy', '.github','node_modules', 'venv', '.venv', 'env', 'vendor', 'packages', '.terraform', '.gradle', '.mvn', '.bundle', 'dist', 'build', 'out', 'target', 'bin', 'obj', '__pycache__', '.git', 'logs', 'tmp', 'temp'}
    ALLOWED_EXTENSIONS = ('.js', '.ts', '.py', '.java', '.xml', '.yml', '.yaml', '.json', '.conf', '.properties', '.sql', '.html')
    
    tree_str = "## Project Directory Structure\n```text\n"
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        depth = root[len(root_dir):].count(os.sep)
        if depth >= max_depth:
            dirs.clear()
            continue
        indent = "  " * depth
        folder_name = os.path.basename(root) if root != root_dir else "."
        tree_str += f"{indent}📂 {folder_name}/\n"
        sub_indent = "  " * (depth + 1)
        valid_files = [f for f in files if f.endswith(ALLOWED_EXTENSIONS) or f in {'Dockerfile', 'pom.xml'}]
        for f in sorted(valid_files):
            tree_str += f"{sub_indent}📄 {f}\n"
    tree_str += "```\n"
    return tree_str

def generate_system_context() -> str:
    """Phase 2, 5에 주입할 글로벌 시스템 및 네트워크 컨텍스트를 반환합니다."""
    return """
[System Environment & Architecture]
- Base OS/Container: Docker (Assumed Ubuntu/Debian base)
- Core Tech Stack: Java 21, Spring Boot 3.3.5, MyBatis, JJWT, Vanilla JS
- Database: SQLite
- Authentication: Strictly Stateless JWT (Authorization Bearer header). No Session Cookies are used.

[Network & Security Perimeter]
1. Network Exposure: The system serves **Public Internet traffic**. External users can reach the application APIs.
2. Edge Proxy: All incoming HTTP/HTTPS traffic is terminated by an Nginx reverse proxy. The Spring Boot application does NOT receive direct internet traffic.
3. WAF: No explicit WAF is currently deployed.
"""

def get_infrastructure_context(root_dir: str) -> str:
    """Trivy 분석에 필요한 핵심 설정 파일들의 내용을 묶어서 반환합니다."""
    context = ""
    target_files = {
        "pom.xml": "backend/pom.xml",
        "application.yml": "backend/src/main/resources/application.yml",
        "Dockerfile": "backend/Dockerfile"
    }
    
    for name, relative_path in target_files.items():
        full_path = os.path.join(root_dir, relative_path)
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
                # 첫 3000자 추출
                context += f"\n### [{name}]\n```\n{content[:3000]}\n```\n"
    return context

def get_merged_snippets(data_flow: list, project_root: str, margin: int = 30) -> str:
    """
    CodeQL의 data_flow 배열을 기반으로 스니펫을 추출합니다.
    Source(최초 오염 발생 지점)는 병합하지 않고 최상단에 명시적으로 분리하여 주입하며,
    라인 번호와 대상 마커를 포함합니다[cite: 7].
    """
    if not data_flow:
        return "No data flow provided."

    snippets = []
    
    # ==========================================
    # 1. Source (첫 번째 노드) 분리 처리
    # ==========================================
    source_node = data_flow[0]
    if ":" in source_node:
        src_filepath, src_line_str = source_node.split(":")
        try:
            src_line = int(src_line_str)
            full_src_path = os.path.join(project_root, src_filepath)
            if os.path.exists(full_src_path):
                with open(full_src_path, 'r', encoding='utf-8', errors='ignore') as f:
                    all_lines = f.readlines()
                    start = max(1, src_line - margin)
                    end = min(len(all_lines), src_line + margin)
                    
                    snippet_lines = []
                    for i, line_content in enumerate(all_lines[start-1:end]):
                        current_line = start + i
                        line_text = line_content.rstrip()
                        
                        marker = ""
                        if current_line == src_line:
                            marker = "  // <--- [CodeQL TARGET LINE]"
                        
                        snippet_lines.append(f"{current_line:4d} | {line_text}")
                        
                    snippet = "\n".join(snippet_lines)
                    snippets.append(f"### [Data Flow SOURCE] File: {src_filepath} (Target Line: {src_line})\n```javascript\n{snippet}\n```\n")
        except ValueError:
            pass

    # ==========================================
    # 2. Intermediate & Sink (나머지 노드) 병합 처리
    # ==========================================
    file_lines = {}
    # Source(인덱스 0)를 제외한 나머지 경로만 병합 대상으로 삼음
    for node in data_flow[1:]: 
        if ":" not in node:
            continue
        filepath, line_str = node.split(":")
        try:
            line_num = int(line_str)
            if filepath not in file_lines:
                file_lines[filepath] = []
            file_lines[filepath].append(line_num)
        except ValueError:
            continue

    if file_lines:
        snippets.append("### ⬇️ [Intermediate & Sink Execution Path]")
    
    for filepath, lines in file_lines.items():
        full_path = os.path.join(project_root, filepath)
        if not os.path.exists(full_path):
            continue
            
        intervals = []
        for l in sorted(lines):
            intervals.append([max(1, l - margin), l + margin])
            
        merged_intervals = []
        for interval in intervals:
            if not merged_intervals or merged_intervals[-1][1] < interval[0] - 1:
                merged_intervals.append(interval)
            else:
                merged_intervals[-1][1] = max(merged_intervals[-1][1], interval[1])
                
        try:
            with open(full_path, 'r', encoding='utf-8', errors='ignore') as f:
                all_lines = f.readlines()
                
            for start, end in merged_intervals:
                actual_end = min(end, len(all_lines))
                
                snippet_lines = []
                for i, line_content in enumerate(all_lines[start-1:actual_end]):
                    current_line = start + i
                    line_text = line_content.rstrip()
                    
                    marker = ""
                    if current_line in lines:  # data_flow에 명시된 라인인 경우
                        marker = "  // <--- [CodeQL TARGET LINE]"
                    
                    # 모든 줄에 라인 번호 강제 표기
                    snippet_lines.append(f"{current_line:4d} | {line_text}{marker}")
                    
                snippet = "\n".join(snippet_lines)
                snippets.append(f"### File: {filepath} (Lines {start}-{actual_end})\n```javascript\n{snippet}\n```\n")
        except Exception as e:
            snippets.append(f"Could not read {filepath}: {e}")

    return "\n".join(snippets)