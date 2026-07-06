import os

def get_project_tree(root_dir: str, max_depth: int = 3) -> str:
    """프로젝트 디렉토리 트리를 텍스트로 추출합니다."""
    IGNORE_DIRS = { 'sample_reports','node_modules', 'venv', '.venv', 'env', 'vendor', 'packages', '.terraform', '.gradle', '.mvn', '.bundle', 'dist', 'build', 'out', 'target', 'bin', 'obj', '__pycache__', '.git', 'logs', 'tmp', 'temp'}
    ALLOWED_EXTENSIONS = ('.js', '.ts', '.py', '.java', '.xml', '.yml', '.yaml', '.json', '.conf', '.properties', '.sql', '.html')
    
    tree_str = "## Project Directory Structure\n```text\n"
    for root, dirs, files in os.walk(root_dir):
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        depth = root[len(root_dir):].count(os.sep)
        if depth >= max_depth:
            dirs.clear()
            continue
        indent = "  " * depth
        folder_name = os.path.basename(root) if root != root_dir else os.path.basename(os.path.abspath(root_dir))
        tree_str += f"{indent}📂 {folder_name}/\n"
        sub_indent = "  " * (depth + 1)
        valid_files = [f for f in files if f.endswith(ALLOWED_EXTENSIONS) or f in {'Dockerfile', 'pom.xml'}]
        for f in sorted(valid_files):
            tree_str += f"{sub_indent}📄 {f}\n"
    tree_str += "```\n"
    return tree_str

def generate_system_context(root_dir: str = ".") -> str:
    """LLM에게 주입할 글로벌 시스템 컨텍스트를 생성합니다."""
    tree_str = get_project_tree(root_dir)
    return f"""
[System Environment & Architecture]
- Base OS/Container: Docker (Assumed Ubuntu/Debian base)
- Core Tech Stack: Java 21, Spring Boot 3.3.5, MyBatis, JJWT, Vanilla JS
- Database: SQLite

{tree_str}
"""

def get_code_snippet(file_path: str, vuln_line: int, radius: int = 30) -> str:
    """SAST 타겟 파일에서 취약점 위아래(±30줄) 코드를 잘라옵니다."""
    if not os.path.exists(file_path):
        return "[Error] File not found. Context unavailable."
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        start = max(0, vuln_line - 1 - radius)
        end = min(len(lines), vuln_line - 1 + radius)
        snippet = "".join(lines[start:end])
        return f"```\n{snippet}\n```"
    except Exception as e:
        return f"[Error] Could not read file: {str(e)}"

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