from __future__ import annotations

import ast
import io
import json
import keyword
import tokenize
from collections import defaultdict
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = PROJECT_ROOT / "src" / "xdr_graph"
TEST_ROOT = PROJECT_ROOT / "tests"
TEMPLATE_PATH = PROJECT_ROOT / "docs" / "code-review-template.html"
OUTPUT_PATH = PROJECT_ROOT / "docs" / "code-review.html"
COVERAGE_PATH = PROJECT_ROOT / "build" / "coverage.json"


GROUP_RULES = (
    ("interface", {"api", "desktop", "cli", "tray", "native_dialogs", "windows_service"}),
    ("collection", {"ingestion", "sysmon_collector", "sysmon_parser", "windows_telemetry", "file_watcher"}),
    ("analysis", {"workflow", "nodes", "detection", "correlation", "model_adapter", "local_model", "risk_policy", "allowlist"}),
    ("graph", {"knowledge_graph", "graph_insights", "retrieval", "commercial_analytics", "exposure_management"}),
    ("response", {"response", "response_execution", "response_playbook", "quarantine", "reporting", "audit"}),
    ("storage", {"storage", "storage_maintenance", "events", "custom_detection"}),
    ("runtime", {"startup", "instance", "security", "self_protection", "runtime_security", "runtime_recovery", "runtime_health", "logging_setup", "update_manager", "version"}),
    ("quality", {"evaluation", "benchmark", "release_validation", "models", "threat_intelligence", "antivirus", "file_scanner"}),
)

GROUP_LABELS = {
    "interface": "UI·API 경계",
    "collection": "수집·정규화",
    "analysis": "탐지·분석",
    "graph": "그래프 조사",
    "response": "대응·보고",
    "storage": "저장·이벤트",
    "runtime": "실행·보호",
    "quality": "검사·품질",
    "other": "기타",
}

# 제품 관점 설명은 파일명이나 docstring을 그대로 노출하지 않고 사용자가 “왜 필요한
# 코드인가”를 이해하도록 입력→처리→출력을 명시한다. 새 모듈은 테스트에서 이 표의
# 누락을 검사하므로 설명 없는 노드가 다시 생기지 않는다.
MODULE_GUIDES = {
    "allowlist": ("신뢰할 수 있는 정상 동작을 탐지 결과에서 구분합니다.", "탐지 결과와 허용 조건을 비교해 억제 여부와 근거를 반환합니다.", "탐지 결과·경로·서명자", "허용 일치·억제된 탐지"),
    "antivirus": ("파일·폴더 검사를 작업 단위로 예약하고 진행 상태를 관리합니다.", "선택 경로를 열거한 뒤 캐시·YARA·Defender 검사를 병렬 제한으로 실행합니다.", "검사 경로·검사 정책", "검사 진행률·파일별 판정"),
    "api": ("대시보드와 내부 서비스 사이의 HTTP 출입구입니다.", "요청을 인증·검증하고 저장소와 분석·대응 서비스를 호출해 안전한 응답으로 변환합니다.", "로컬 HTTP 요청", "사건·조사·운영 JSON 또는 정적 UI"),
    "api_schemas": ("API로 들어오는 값의 형식과 허용 범위를 정의합니다.", "Pydantic이 길이·종류·필수 여부를 라우트 실행 전에 검사합니다.", "요청 JSON", "검증된 요청 객체 또는 422 오류"),
    "audit": ("누가 어떤 대응과 설정 변경을 시도했는지 감사 기록을 남깁니다.", "행동·대상·결과·시각을 변조하기 어려운 순서형 로그로 저장합니다.", "사용자 행동·대응 결과", "감사 레코드"),
    "benchmark": ("로컬 AI 모델 후보의 정확도와 지연을 같은 조건에서 비교합니다.", "고정 평가 사례를 반복 실행해 오탐·미탐·지연 통계를 계산합니다.", "평가 데이터·모델", "모델 비교 보고서"),
    "cli": ("개발자와 자동화가 분석 흐름을 명령줄에서 실행하게 합니다.", "입력 파일과 모델 옵션을 읽어 워크플로를 실행하고 결과를 직렬화합니다.", "명령행 옵션·사건 입력", "분석 결과 JSON"),
    "commercial_analytics": ("상용 XDR처럼 엔터티 위험과 공격 스토리를 요약합니다.", "공유 사용자·프로세스·파일·IP를 기준으로 여러 사건을 묶고 위험 기여도를 계산합니다.", "사건 목록", "엔터티 위험·공격 스토리"),
    "correlation": ("서로 떨어진 이벤트를 하나의 사건 후보로 연결합니다.", "시간 창과 호스트·프로세스·파일·IP 공통점을 이용해 관련 이벤트를 그룹화합니다.", "정규화 보안 이벤트", "상관 사건 묶음"),
    "custom_detection": ("저장한 헌팅 조건을 반복 탐지 규칙으로 운영합니다.", "만기 규칙만 제한 조회하고 섀도 결과와 예상 탐지량을 저장한 뒤 사용자 확인 후 활성화합니다.", "저장 검색·반복 주기", "규칙 상태·탐지 샘플"),
    "desktop": ("EXE 실행 시 모든 백엔드 서비스를 조립하고 브라우저 수명을 관리합니다.", "단일 인스턴스·포트·저장소·수집기·API·트레이를 순서대로 준비하고 정상 종료를 조정합니다.", "환경 설정·로컬 데이터", "실행 중인 WeaveXDR 데스크톱"),
    "detection": ("정규화 이벤트에 탐지 규칙을 적용합니다.", "행동 패턴과 위협 참고 정보를 비교해 판정·위험도·MITRE 근거를 만듭니다.", "보안 이벤트·탐지 규칙", "탐지 결과 목록"),
    "evaluation": ("탐지·AI 워크플로의 기대 결과를 회귀 평가합니다.", "정답이 있는 사례를 실행 결과와 비교해 성공 여부와 차이를 계산합니다.", "평가 사례", "평가 점수·실패 상세"),
    "events": ("사건 변경을 대시보드의 실시간 스트림으로 전달합니다.", "발행된 사건 ID를 구독자별 큐에 복제하고 종료 시 안전하게 연결을 해제합니다.", "사건 변경 알림", "구독자 이벤트 스트림"),
    "exposure_management": ("장치·소프트웨어·신원·네트워크의 보호 공백을 점수화합니다.", "로컬 자산과 관찰 사건만 근거로 영역별 점수와 개선 권고를 계산합니다.", "자산 목록·사건·운영 상태", "보호 점수·개선 권고"),
    "feedback": ("사용자 판정 교정을 탐지 개선 자료로 바꿉니다.", "오탐·정탐 피드백을 허용 정책과 평가 사례 후보로 정규화합니다.", "사용자 피드백", "허용 조건·평가 후보"),
    "file_scanner": ("개별 파일의 해시·서명·YARA·Defender 근거를 수집합니다.", "파일을 안전하게 읽고 여러 검사기의 결과를 합쳐 단일 판정을 만듭니다.", "파일 경로", "파일 검사 결과"),
    "file_watcher": ("중요 폴더에 새로 생기거나 바뀐 파일을 감시합니다.", "디렉터리 변경을 주기적으로 비교하고 새 항목만 검사 엔진으로 전달합니다.", "감시 폴더·이전 상태", "변경 파일 검사 이벤트"),
    "graph_insights": ("사건 그래프에서 조사자가 볼 관계·경로·가설을 계산합니다.", "홉 탐색·최단 경로·관계 분포·희귀 조합을 제한된 그래프에서 분석합니다.", "사건 보고서·그래프 질문", "관계 분석·공격 가설"),
    "ingestion": ("서로 다른 센서 이벤트를 공통 사건 형식으로 받아들입니다.", "배치를 검증·중복 제거하고 워크플로 분석 뒤 저장소에 전달합니다.", "정규화 이벤트 배치", "저장된 사건 보고서"),
    "investigation_patterns": ("시간 순서와 과거 사건이 필요한 고급 조사 패턴을 계산합니다.", "다단계 파일 유입·실행·지속성, 파일 신원 변화, 과거 서브그래프와 노드 정리 후보를 근거 ID와 함께 만듭니다.", "현재 사건·과거 사건·그래프", "연쇄 탐지·중첩 그래프·잡음·병합 후보"),
    "instance": ("WeaveXDR가 중복 실행되지 않도록 인스턴스와 인증 비밀을 조정합니다.", "PID·포트·버전 메타데이터와 DPAPI 보호 토큰을 확인해 기존 실행본 재열기 여부를 결정합니다.", "실행 프로세스·포트", "인스턴스 레코드·세션 비밀"),
    "knowledge_graph": ("여러 사건에서 반복되는 Host·Process·File·IP 관계를 장기 저장합니다.", "엔터티를 중복 제거한 노드와 타입 관계로 저장하고 홉·유사 사건 조회를 제공합니다.", "사건 보고서", "속성 그래프·연결 경로"),
    "local_model": ("Ollama 설치 모델과 PC 사양별 추천 상태를 관리합니다.", "모델 목록·자원 상태를 확인하고 선택·설치·상주 상태를 안전하게 보고합니다.", "Ollama 상태·PC 사양", "모델 추천·설치 상태"),
    "logging_setup": ("운영 로그가 디스크를 무제한 사용하지 않도록 순환 기록을 설정합니다.", "크기와 보관 개수가 제한된 파일 핸들러를 구성합니다.", "로그 경로·레벨", "회전 로그 설정"),
    "model_adapter": ("분석 워크플로가 규칙 모델과 Ollama를 같은 방식으로 호출하게 합니다.", "공통 입력을 모델별 형식으로 바꾸고 실패 시 규칙 결과로 안전하게 대체합니다.", "사건·탐지 근거", "모델 판정·비교 결과"),
    "models": ("프로그램 전체가 공유하는 사건·이벤트·탐지 데이터 구조를 정의합니다.", "Pydantic 타입으로 필드와 직렬화 계약을 통일합니다.", "원시 필드 값", "검증된 도메인 객체"),
    "native_dialogs": ("브라우저 대신 Windows 기본 파일·폴더 선택창을 엽니다.", "최상위 소유 창에서 네이티브 대화상자를 실행하고 선택 경로만 반환합니다.", "선택 종류", "사용자가 고른 경로"),
    "nodes": ("LangGraph 분석 단계별 실제 처리 함수를 제공합니다.", "상관분석·탐지·허용목록·위험 점수·모델·검증 단계를 상태에 차례로 적용합니다.", "IncidentState", "단계별 갱신 상태"),
    "quarantine": ("격리한 파일의 원본 위치와 복구 정보를 안전하게 보관합니다.", "파일을 격리 저장소로 옮기고 해시·메타데이터를 기록해 승인된 복원을 지원합니다.", "의심 파일·승인", "격리 레코드·복원 결과"),
    "release_validation": ("배포 폴더와 업데이트 자산이 릴리스 계약을 만족하는지 검사합니다.", "필수 파일·버전·해시·매니페스트·ZIP 구조를 교차 검증합니다.", "릴리스 트리·매니페스트", "검증 오류 목록"),
    "reporting": ("사건과 보호 상태를 사람이 읽거나 공유할 보고서로 내보냅니다.", "민감정보 마스킹 후 HTML·PDF·CSV·JSON·STIX 형식으로 변환합니다.", "사건·요약·내보내기 옵션", "보고서 파일"),
    "response": ("대응 명령의 정책·승인·미리보기 계약을 정의합니다.", "위험 작업을 기본 dry-run으로 만들고 승인 레코드와 실행 조건을 검증합니다.", "사건·대응 요청", "명령·미리보기·승인 상태"),
    "response_execution": ("승인된 프로세스 종료·격리·네트워크 차단을 실제로 수행합니다.", "실행 직전 대상을 재검증하고 감사·복구 기록을 남기며 단계별 실패를 중단합니다.", "승인된 대응 명령", "실행 결과·복구 레코드"),
    "response_playbook": ("여러 대응 단계를 순서와 승인 조건이 있는 플레이북으로 묶습니다.", "각 단계의 영향 범위를 먼저 시뮬레이션하고 승인된 단계만 순차 실행합니다.", "플레이북·단계별 승인", "시뮬레이션·실행 결과"),
    "retrieval": ("질문과 관련된 과거 사건·그래프 근거를 찾습니다.", "키워드 검색과 공유 엔터티 그래프 검색을 제한 결과로 결합합니다.", "조사 질문·현재 사건", "근거 사건·그래프 문맥"),
    "risk_policy": ("여러 탐지 결과를 일관된 사건 위험도로 환산합니다.", "판정·심각도·근거 수에 정책 가중치를 적용하고 상한을 보정합니다.", "탐지 결과", "위험 점수·판정"),
    "runtime_health": ("실행 중 CPU·메모리·디스크·센서 지연을 감시합니다.", "주기 표본과 변화율을 계산해 저전력·장기 증가·수집 공백 상태를 보고합니다.", "프로세스·시스템 표본", "런타임 건강 상태"),
    "runtime_recovery": ("비정상 종료 뒤 데이터와 런타임 상태를 안전하게 복구합니다.", "잠금·DB 무결성·백업을 확인하고 필요한 최소 복구만 수행합니다.", "시작 상태·저장소", "복구 보고서"),
    "runtime_security": ("실행 환경의 위험한 설정과 권한을 시작 전에 검사합니다.", "바인딩 주소·토큰·파일 권한·보안 옵션을 정책과 비교합니다.", "실행 설정", "보안 검증 결과"),
    "security": ("로컬 비밀과 데이터 파일의 Windows 보호 처리를 제공합니다.", "DPAPI 암복호화와 ACL 강화를 통해 현재 사용자 또는 SYSTEM 범위로 제한합니다.", "비밀·데이터 경로", "보호된 값·권한 결과"),
    "self_protection": ("실행 파일과 핵심 설정의 누락·변경·추가를 감시합니다.", "기준 해시와 현재 파일을 비교하고 변경 종류와 보호 상태를 반환합니다.", "보호 매니페스트·현재 파일", "무결성 차이·경고"),
    "startup": ("Windows 로그인 시 자동 시작 여부를 명시적으로 관리합니다.", "사용자 선택에 따라 시작 등록을 추가·제거하고 현재 상태를 조회합니다.", "자동 시작 설정", "등록 상태"),
    "static_assets": ("대시보드 HTML·지도·아이콘을 소스와 EXE에서 동일하게 읽습니다.", "실행 위치를 판별하고 정적 파일을 프로세스당 한 번 캐시합니다.", "정적 자원 이름", "HTML·SVG·ICO 데이터"),
    "storage": ("사건·이벤트·사용자 상태를 SQLite에 저장하고 조회합니다.", "트랜잭션·인덱스·페이지 제한을 적용하고 저장 뒤 변경 이벤트를 발행합니다.", "사건·이벤트·조회 조건", "영속 레코드·페이지 결과"),
    "storage_maintenance": ("DB 크기·보존·백업·복구 수명 주기를 관리합니다.", "무결성 검사·정리·최적화·백업·복원 리허설을 원자적 단계로 수행합니다.", "SQLite DB·보존 정책", "건강 상태·백업·복구 결과"),
    "sysmon_collector": ("Windows Sysmon 이벤트를 실시간으로 읽어 수집 파이프라인에 전달합니다.", "구독 이벤트를 XML 파서로 정규화하고 손실·지연 상태와 함께 배치 전송합니다.", "Sysmon 이벤트 스트림", "정규화 이벤트 배치"),
    "sysmon_parser": ("Sysmon XML을 공통 Process·Network·File 이벤트로 변환합니다.", "이벤트 ID별 필드를 추출하고 시간·GUID·경로·IP를 표준 타입으로 정리합니다.", "Sysmon XML", "SecurityEvent 객체"),
    "threat_intelligence": ("IOC·STIX·Sigma·GeoIP 콘텐츠를 검증하고 버전 관리합니다.", "출처·해시·스키마를 확인한 콘텐츠만 임시 저장 후 원자적으로 적용합니다.", "위협 콘텐츠 파일", "검증된 IOC·규칙·버전 상태"),
    "tray": ("Windows 알림 영역에서 대시보드 열기와 종료를 제공합니다.", "백그라운드 메시지 루프가 아이콘 메뉴를 API 수명 콜백과 연결합니다.", "사용자 트레이 동작", "대시보드 열기·종료 요청"),
    "update_manager": ("GitHub 릴리스 업데이트를 확인하고 안전한 적용 준비를 합니다.", "버전·해시·매니페스트를 검증해 새 자산을 내려받고 적용 콜백에 넘깁니다.", "현재 버전·릴리스 메타데이터", "업데이트 상태·검증 자산"),
    "version": ("앱 버전과 빌드 날짜의 단일 기준을 제공합니다.", "API·UI·EXE·릴리스 검증이 같은 상수를 읽습니다.", "없음", "버전·빌드 날짜"),
    "windows_service": ("WeaveXDR를 Windows 서비스 모드로 실행합니다.", "서비스 시작·중지 신호를 데스크톱과 같은 API·수집 수명 주기에 연결합니다.", "서비스 제어 신호", "백그라운드 XDR 서비스"),
    "windows_telemetry": ("Security·PowerShell·Defender 등 확장 Windows 로그를 수집합니다.", "채널별 이벤트를 공통 스키마로 변환하고 지연·손실 메타데이터를 배치에 포함합니다.", "Windows 이벤트 로그", "정규화 텔레메트리 배치"),
    "workflow": ("하나의 사건을 수집부터 최종 보고까지 처리하는 LangGraph 순서를 정의합니다.", "분석 노드를 상태 그래프로 연결하고 오류·대체 경로와 최종 상태를 통제합니다.", "IncidentInput·서비스 의존성", "IncidentReport·에이전트 추적"),
}

TECHNIQUES = {
    "sqlite3": ("SQLite", "인덱스와 제한 조회를 사용하는 영속 저장소"),
    "RLock": ("재진입 잠금", "여러 스레드가 공유 상태를 변경할 때 경쟁 상태를 방지"),
    "Lock": ("상호 배제 잠금", "공유 자원에 대한 동시 접근을 직렬화"),
    "Event": ("이벤트 플래그", "백그라운드 작업의 시작·중단·종료 상태를 전달"),
    "Queue": ("스레드 안전 큐", "생산자와 소비자 사이의 작업을 순서대로 전달"),
    "deque": ("양방향 큐", "앞뒤 삽입·삭제가 잦은 버퍼를 O(1)에 처리"),
    "heapq": ("우선순위 큐", "우선도가 높은 항목을 먼저 꺼내는 힙 자료구조"),
    "defaultdict": ("기본값 딕셔너리", "그룹화와 누적 집계를 조건문 없이 처리"),
    "dataclass": ("데이터 클래스", "상태 전달 객체의 반복 코드를 줄이고 타입을 명확화"),
    "BaseModel": ("Pydantic 검증", "API 입출력의 타입·길이·범위를 경계에서 검증"),
    "lru_cache": ("LRU 캐시", "반복 계산이나 정적 자원 읽기를 재사용"),
    "ThreadPoolExecutor": ("스레드 풀", "독립적인 I/O 작업을 제한된 병렬도로 처리"),
    "asyncio": ("비동기 실행", "대기 시간이 긴 작업 동안 다른 요청 처리를 허용"),
    "subprocess": ("격리 프로세스", "Defender·PowerShell 같은 외부 도구를 제한 시간과 함께 실행"),
    "hashlib": ("암호학적 해시", "파일 식별과 무결성 검증에 SHA 계열 해시를 사용"),
    "hmac": ("HMAC", "요청 메타데이터의 위변조 여부를 비밀키 기반으로 확인"),
    "re.": ("정규 표현식", "로그·경로·명령 문자열에서 패턴을 추출"),
    "networkx": ("그래프 알고리즘", "노드와 관계를 그래프 자료구조로 분석"),
    "shortest": ("최단 경로 탐색", "관계 그래프에서 조사 대상까지 가장 짧은 연결을 계산"),
    "breadth": ("너비 우선 탐색", "홉 단위로 인접 노드를 단계적으로 확장"),
    "dfs": ("깊이 우선 탐색", "연결 요소와 경로를 재귀 또는 스택으로 탐색"),
    "bisect": ("이진 탐색", "정렬된 데이터에서 삽입·검색 위치를 O(log n)에 계산"),
}


def module_group(name: str) -> str:
    for group, members in GROUP_RULES:
        if name in members:
            return group
    return "other"


def internal_imports(tree: ast.AST) -> set[str]:
    dependencies: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            if node.module == "xdr_graph":
                for alias in node.names:
                    dependencies.add(alias.name.split(".")[0])
            elif node.module.startswith("xdr_graph."):
                dependencies.add(node.module.split(".")[1])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("xdr_graph."):
                    dependencies.add(alias.name.split(".")[1])
    return dependencies


def complexity(node: ast.AST) -> int:
    branch_nodes = (
        ast.If,
        ast.For,
        ast.AsyncFor,
        ast.While,
        ast.Try,
        ast.BoolOp,
        ast.IfExp,
        ast.Match,
        ast.comprehension,
    )
    # 중첩 함수·메서드는 별도 심볼로 집계한다. 부모 함수 복잡도에 다시 더하면
    # create_app 같은 라우트 팩토리가 실제보다 과장되므로 해당 경계에서 순회를 멈춘다.
    score = 1
    pending = list(ast.iter_child_nodes(node))
    while pending:
        child = pending.pop()
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            continue
        score += isinstance(child, branch_nodes)
        pending.extend(ast.iter_child_nodes(child))
    return score


def signature(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    arguments = [argument.arg for argument in node.args.posonlyargs + node.args.args]
    if node.args.vararg:
        arguments.append(f"*{node.args.vararg.arg}")
    arguments.extend(argument.arg for argument in node.args.kwonlyargs)
    if node.args.kwarg:
        arguments.append(f"**{node.args.kwarg.arg}")
    prefix = "async " if isinstance(node, ast.AsyncFunctionDef) else ""
    return f"{prefix}{node.name}({', '.join(arguments)})"


def symbols(tree: ast.Module) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    def visit(node: ast.AST, scope: tuple[str, ...], parent_kind: str = "module") -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            qualified_name = ".".join((*scope, node.name))
            kind = "method" if parent_kind == "class" else "local function" if parent_kind == "function" else "function"
            result.append(
                {
                    "name": qualified_name,
                    "kind": kind,
                    "signature": signature(node),
                    "line": node.lineno,
                    "endLine": node.end_lineno or node.lineno,
                    "complexity": complexity(node),
                    "doc": ast.get_docstring(node) or "",
                }
            )
            next_scope = (*scope, node.name)
            next_parent = "function"
        elif isinstance(node, ast.ClassDef):
            qualified_name = ".".join((*scope, node.name))
            methods = [
                child
                for child in node.body
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            result.append(
                {
                    "name": qualified_name,
                    "kind": "class",
                    "signature": f"class {node.name}",
                    "line": node.lineno,
                    "endLine": node.end_lineno or node.lineno,
                    "complexity": 0,
                    "doc": ast.get_docstring(node) or "",
                    "methods": [signature(method) for method in methods],
                }
            )
            next_scope = (*scope, node.name)
            next_parent = "class"
        else:
            next_scope = scope
            next_parent = parent_kind
        for child in ast.iter_child_nodes(node):
            visit(child, next_scope, next_parent)

    for node in tree.body:
        visit(node, ())
    result.sort(key=lambda item: (item["line"], item["name"]))
    return result


def detected_techniques(source: str) -> list[dict[str, str]]:
    found: list[dict[str, str]] = []
    for token, (name, description) in TECHNIQUES.items():
        if token in source:
            found.append({"name": name, "description": description})
    if "dict[" in source or ": dict" in source:
        found.append({"name": "해시 맵", "description": "키 기반 조회와 상태 연결을 평균 O(1)에 처리"})
    if "set[" in source or ": set" in source:
        found.append({"name": "집합", "description": "중복 제거와 포함 여부 검사를 평균 O(1)에 처리"})
    if "list[" in source or ": list" in source:
        found.append({"name": "동적 배열", "description": "순서가 있는 사건·결과 묶음을 연속적으로 보관"})
    return found


def source_tokens(source: str) -> list[dict[str, object]]:
    """Return line-local semantic spans so the offline page needs no highlighter."""
    source_lines = source.splitlines()
    raw_tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
    significant = [
        index
        for index, token in enumerate(raw_tokens)
        if token.type not in {tokenize.ENCODING, tokenize.NL, tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT}
    ]
    previous_by_index: dict[int, tokenize.TokenInfo | None] = {}
    next_by_index: dict[int, tokenize.TokenInfo | None] = {}
    for position, index in enumerate(significant):
        previous_by_index[index] = raw_tokens[significant[position - 1]] if position else None
        next_by_index[index] = raw_tokens[significant[position + 1]] if position + 1 < len(significant) else None

    spans: list[dict[str, object]] = []
    for index, token in enumerate(raw_tokens):
        kind = ""
        previous = previous_by_index.get(index)
        following = next_by_index.get(index)
        if token.type == tokenize.COMMENT:
            kind = "comment"
        elif token.type == tokenize.STRING:
            kind = "string"
        elif token.type == tokenize.NUMBER:
            kind = "number"
        elif token.type == tokenize.NAME:
            if keyword.iskeyword(token.string):
                kind = "keyword"
            elif previous and previous.string == "def":
                kind = "function"
            elif previous and previous.string == "class":
                kind = "class"
            elif previous and previous.string == "@":
                kind = "decorator"
            elif following and following.string == "(":
                kind = "call"
            elif following and following.string in {"=", ":="}:
                kind = "variable"
            else:
                kind = "identifier"
        if not kind:
            continue
        for line_number in range(token.start[0], token.end[0] + 1):
            line_text = source_lines[line_number - 1] if source_lines else ""
            start = token.start[1] if line_number == token.start[0] else 0
            end = token.end[1] if line_number == token.end[0] else len(line_text)
            if end > start:
                spans.append({"line": line_number, "start": start, "end": end, "kind": kind})
    return spans


def test_import_map() -> tuple[dict[str, set[str]], int]:
    mapping: dict[str, set[str]] = defaultdict(set)
    test_count = 0
    for path in sorted(TEST_ROOT.glob("test_*.py")):
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        test_count += sum(
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
            for node in ast.walk(tree)
        )
        for dependency in internal_imports(tree):
            mapping[dependency].add(path.name)
        conventional_name = path.stem.removeprefix("test_")
        if (SOURCE_ROOT / f"{conventional_name}.py").exists():
            mapping[conventional_name].add(path.name)
    return mapping, test_count


def build_report() -> dict[str, object]:
    tests_by_module, test_count = test_import_map()
    coverage_data = json.loads(COVERAGE_PATH.read_text(encoding="utf-8")) if COVERAGE_PATH.exists() else {}
    coverage_files = {
        path.replace("\\", "/"): metrics
        for path, metrics in coverage_data.get("files", {}).items()
    }
    modules: list[dict[str, object]] = []
    dependents: dict[str, set[str]] = defaultdict(set)

    for path in sorted(SOURCE_ROOT.glob("*.py")):
        name = path.stem
        if name == "__init__":
            continue
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(path))
        dependencies = sorted(dependency for dependency in internal_imports(tree) if dependency != name)
        for dependency in dependencies:
            dependents[dependency].add(name)
        module_symbols = symbols(tree)
        role, flow, inputs, outputs = MODULE_GUIDES.get(
            name,
            ("설명이 아직 등록되지 않은 내부 모듈입니다.", "소스 구조를 직접 확인하세요.", "미정", "미정"),
        )
        relative_path = path.relative_to(PROJECT_ROOT).as_posix()
        coverage = coverage_files.get(relative_path, {}).get("summary", {}).get("percent_covered")
        modules.append(
            {
                "id": name,
                "label": name.replace("_", " "),
                "group": module_group(name),
                "path": relative_path,
                "summary": role,
                "flow": flow,
                "inputs": inputs,
                "outputs": outputs,
                "codeDoc": (ast.get_docstring(tree) or "모듈 docstring 없음").split("\n", 1)[0],
                "lines": len(source.splitlines()),
                "nonBlank": sum(bool(line.strip()) for line in source.splitlines()),
                "complexity": sum(item["complexity"] for item in module_symbols if item["kind"] != "class"),
                "dependencies": dependencies,
                "symbols": module_symbols,
                "techniques": detected_techniques(source),
                "tests": sorted(tests_by_module.get(name, set())),
                "coverage": round(coverage, 1) if coverage is not None else None,
                "sourceTokens": source_tokens(source),
                "source": source,
            }
        )

    known_modules = {module["id"] for module in modules}
    for module in modules:
        module["dependencies"] = [item for item in module["dependencies"] if item in known_modules]
        module["dependents"] = sorted(dependents.get(module["id"], set()) & known_modules)

    edges = [
        {"source": module["id"], "target": dependency}
        for module in modules
        for dependency in module["dependencies"]
    ]
    return {
        "modules": modules,
        "edges": edges,
        "groups": GROUP_LABELS,
        "summary": {
            "moduleCount": len(modules),
            "sourceLines": sum(module["nonBlank"] for module in modules),
            "symbolCount": sum(len(module["symbols"]) for module in modules),
            "testCount": test_count,
            "directlyTestedModules": sum(bool(module["tests"]) for module in modules),
            "coverage": round(coverage_data.get("totals", {}).get("percent_covered", 0), 1) if coverage_data else None,
        },
    }


def main() -> None:
    report = build_report()
    template = TEMPLATE_PATH.read_text(encoding="utf-8")
    payload = json.dumps(report, ensure_ascii=False).replace("</", "<\\/")
    output = template.replace("/*__CODE_REVIEW_DATA__*/", f"window.CODE_REVIEW_DATA = {payload};")
    OUTPUT_PATH.write_text(output, encoding="utf-8", newline="\n")
    print(f"generated {OUTPUT_PATH} ({len(report['modules'])} modules)")


if __name__ == "__main__":
    main()
