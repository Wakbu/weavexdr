# Personal XDR Graph Skeleton

개인용 AI XDR을 위한 LangGraph 실행 골격이다. 샘플 이벤트로 병렬 분석, 종합, 검증, 재평가와 보고서 출력을 확인하며, 종합 노드는 결정론적 규칙 모델 또는 정책 가드가 적용된 Ollama 로컬 모델을 선택할 수 있다. 실제 Windows 보안 도구는 아직 연결하지 않았다.

## 현재 그래프

```text
normalize
  ├─ file_analysis ─────┐
  ├─ behavior_analysis ─┼─> synthesize -> verify -> report
  └─ network_analysis ──┘                    │
                                             └-> reassess -> verify
```

## 공통 이벤트 스키마

그래프 입력은 `schema_version`, `event_id`, `event_type`, 시간대가 포함된 `timestamp`, `host_id`, `source`를 공통 필드로 사용한다. `event_type`에 따라 프로세스 생성, 파일 생성과 네트워크 연결의 필수 필드를 개별 검증한다. 현재 스키마 버전은 `1.0`이다.

- 알 수 없는 정규화 필드는 거부
- PID와 포트 범위 검증
- 네트워크 IP 형식 검증
- 프로세스 시작 시각이 있으면 시간대 필수
- 기존 샘플 입력에는 `local-host`, `sample`, `1.0` 기본값 적용

## 수집기 입력 인터페이스

수집기는 정규화된 `NormalizedEventBatch`를 `EventBatchSink`에 전달한다. `GraphIngestionService`는 배치와 이벤트 계약을 검증한 뒤 LangGraph를 실행하고, `PersistentIngestionService`는 SQLite 저장과 배치 간 중복 제거를 더한 뒤 `IngestionReceipt`를 반환한다.

- 배치 ID, 사건 ID, 수집기 ID와 수신 시각 필수
- 배치 내부 이벤트 ID 중복 거부
- 잘못된 이벤트는 그래프 실행 전에 거부
- 배치 간 `event_id` 중복 제거 및 수락·중복 개수 반환
- 같은 사건에 나중에 도착한 이벤트를 기존 증거와 합쳐 재분석

```powershell
.\.venv\Scripts\python.exe -m xdr_graph.ingestion .\samples\suspicious_office_batch.json
```

## 이벤트 저장과 버퍼

`SQLiteEventStore`는 원본 정규화 이벤트, 배치 처리 이력과 사건별 최신 보고서를 기본 30일 동안 저장한다. `EventBuffer`는 이벤트 수 기준 고정 용량 큐이며, 저장 실패 시 배치를 제거하지 않아 재시도할 수 있다. 운영 코드에서는 다음과 같이 수집 파이프라인에 영속 입력 서비스를 주입한다.

```python
from xdr_graph.storage import EventBuffer, PersistentIngestionService, SQLiteEventStore
from xdr_graph.sysmon_parser import SysmonGraphPipeline

store = SQLiteEventStore("data/xdr.db", retention_days=30)
service = PersistentIngestionService(store)
pipeline = SysmonGraphPipeline(ingestion_service=service)
buffer = EventBuffer(service, capacity=1000)

# 주기적인 유지보수 작업에서 호출한다.
removed = store.cleanup_expired()
```

## 파일 검사 엔진

`FileInspectionEngine`은 실제 파일을 읽어 SHA-256, 크기, 수정 시각과 MIME 유형을 수집하고 다음 검사 결과를 공통 `Finding`으로 변환한다.

- Windows Authenticode 서명 상태와 서명자
- `rules/file_scan.yar` 기반 YARA 규칙 일치
- Microsoft Defender 사용자 지정 검사와 위협 이름
- 잘못된 서명, YARA 탐지와 Defender 탐지를 파일 근거로 정규화

Defender 검사는 Windows 권한 정책에 따라 관리자 권한이 필요할 수 있다. 검사 실패는 정상 판정으로 바꾸지 않고 `scanned=False`와 오류 내용으로 반환한다.

검사 엔진은 기본 100MB 파일 크기 제한과 서명·YARA·Defender별 시간 제한을 적용한다. 일부 검사기가 실패해도 완료된 해시와 다른 검사 결과는 `errors`와 함께 보존한다.

`DirectoryFileWatcher`는 기본적으로 다운로드와 임시 폴더의 신규 파일을 폴링한다. 파일 크기와 수정 시각이 두 번 연속 같을 때만 검사해 다운로드 중인 파일을 피하며, 심볼릭 링크와 기존 파일은 자동 검사하지 않는다. 감시 결과는 `FileCreateEvent`와 `FileInspectionResult`를 함께 제공하므로 다음 상관분석 단계에서 사건 그래프에 연결할 수 있다.

## 설정 기반 탐지와 상관분석

기본 탐지 규칙은 `config/detection-rules.json`, 위험 점수와 판정 임계값은 `config/risk-policy.json`에서 관리한다.

- 규칙마다 OWASP·MITRE ATT&CK·CISA 등 출처 버전과 공식 URL 기록
- 새 규칙 묶음의 스키마·중복·HTTPS 출처·SHA-256 검증 후 활성화
- 문제 발생 시 직전 규칙 묶음으로 롤백
- 기본 점수 판정: 0~34 `benign`, 35~69 `needs_review`, 70 이상 `suspicious`
- `suspicious`는 서로 다른 분석 출처가 두 개 미만이면 독립 검증 노드가 `needs_review`로 낮춤
- 기본 5분 범위에서 ProcessGuid 또는 PID·시작 시각으로 프로세스·파일·네트워크 연결
- 부모 ProcessGuid를 따라 프로세스 트리와 원본 이벤트 ID가 포함된 공격 흐름 생성

## 근거 추적과 오탐 관리

사건 보고서는 판정에 사용된 `Finding`, 허용 목록으로 제외된 탐지, 공격 흐름과 정규화 원본 이벤트를 함께 보존한다. 따라서 점수와 설명에서 원본 `event_id`까지 역추적할 수 있다.

`config/allowlist.json`의 정상 행위 예외는 다음 안전 조건을 적용한다.

- 규칙 ID만으로 전체 탐지를 끌 수 없으며 호스트·프로세스·경로·SHA-256 중 하나 이상 필수
- 활성화와 검토자 승인 상태를 모두 요구
- 시간대가 포함된 만료 시각 필수
- 여러 이벤트를 묶은 상관 탐지는 모든 원본 이벤트가 조건에 맞아야 제외
- 제외된 탐지도 삭제하지 않고 보고서와 SQLite 피드백 기록에 보존

오탐 피드백은 서로 다른 사건에서 두 번 이상 검토자 승인을 받아야 허용 목록·회귀 평가 후보가 된다. 후보 반영에는 다시 명시적 확인이 필요하며 자동으로 탐지 규칙을 비활성화하지 않는다.

## 대응 dry-run과 승인

`config/response-policy.json`은 허용된 대응, 승인이 필요한 대응과 보호할 Windows 프로세스·경로를 정의한다. 현재 `DryRunResponseService`는 대응 가능 여부만 검사하며 운영체제 명령을 호출하지 않는다.

- 명령은 사건 ID, 대상 식별 정보와 시간대가 포함된 요청 시각을 요구
- 프로세스 종료는 PID와 프로세스 시작 시각을 함께 요구
- 파일 격리는 전체 경로와 SHA-256을 요구
- 검증된 사건 보고서가 권고하지 않은 대응은 차단
- Windows 핵심 프로세스와 보호 경로 대상은 승인 전 단계에서 차단
- 종료·격리 승인은 명령 ID에 귀속되며 기본 10분 뒤 만료
- 현재 모든 결과는 `executed=False`이며 실제 종료·격리는 W11 전까지 불가능

## Sysmon 수집 환경

Microsoft Sysmon 15.21 서비스와 드라이버를 설정 스키마 4.91로 설치했다. 프로젝트 기준 설정은 `config/sysmon-minimal.xml`, 실제 적용 사본은 `C:\ProgramData\PersonalXDR\sysmon-minimal.xml`이다.

- Event ID 1: 모든 프로세스 생성
- Event ID 3: 스크립트 인터프리터와 사용자 쓰기 경로의 네트워크 연결
- Event ID 11: 실행 파일과 스크립트 생성
- 해시: SHA256, IMPHASH
- 실제 Operational 로그에서 Event ID 1·3·11 수집 확인

Operational 로그 확인에는 관리자 권한이 필요할 수 있다.

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\scripts\verify_sysmon.ps1 -OutputPath C:\ProgramData\PersonalXDR\sysmon-verification.json
```

## Sysmon 파이프라인

`SysmonXmlParser`는 Windows Event XML을 공통 이벤트 스키마로 변환한다.

- Event ID 1 → `ProcessStartEvent`
- Event ID 3 → `NetworkConnectEvent`
- Event ID 11 → `FileCreateEvent`
- `ProcessGuid` → PID 재사용과 무관한 프로세스 시작 정보 상관관계
- `SysmonGraphPipeline` → XML 묶음을 `GraphIngestionService`와 분석 그래프에 전달

실제 설치된 Sysmon에서 Event ID 1·3·11 최신 XML을 각각 내보내 파서 호환성을 확인했다. 테스트에 사용한 실제 XML은 명령줄과 사용자 경로를 포함할 수 있어 확인 직후 삭제한다.

```powershell
.\.venv\Scripts\python.exe -m xdr_graph.sysmon_parser <event-1.xml> <event-3.xml> <event-11.xml>
```

## 실행

프로젝트 가상환경에 개발 의존성이 설치된 상태에서 실행한다.

```powershell
.\.venv\Scripts\python.exe -m xdr_graph.cli .\samples\suspicious_office_chain.json
```

로컬 모델을 사용하는 경우에도 정책 가드와 규칙 모델 대체 경로가 적용된다.

```powershell
.\.venv\Scripts\python.exe -m xdr_graph.cli .\samples\suspicious_office_chain.json --provider ollama --model qwen3:8b
```

## 테스트

```powershell
.\.venv\Scripts\python.exe -m pytest -q
```

테스트는 그래프 판정, 이벤트 저장, 파일 감시, 상관분석, 오탐 관리와 대응 안전 정책을 검증한다. 현재 전체 결과는 `88 passed`, 기준 평가는 `30/30 passed`다.

## 기준 평가

30개 보안 사건의 기대 판정, 점수 범위와 필수 탐지 규칙을 검사한다.

```powershell
.\.venv\Scripts\python.exe -m xdr_graph.evaluation .\evaluations\incidents.json
```

현재 결정론적 기준 모델의 결과는 `30/30 passed`다. `qwen3:8b`도 정책 가드 적용 상태에서 30건 모두 기대 판정과 일치했다.

```powershell
.\.venv\Scripts\python.exe -m xdr_graph.benchmark .\evaluations\incidents.json --model qwen3:8b
```

## 범위 밖

다음 항목은 후속 채팅에서 별도로 구현한다.

- Sysmon 실시간 이벤트 수집
- 파일 검사 결과와 사건 그래프의 상관분석
- 실제 프로세스 종료와 파일 격리
- 장기 보안 지식 그래프

상세 설계는 [XDR AI 그래프 엔지니어링 설계 정리](XDR_AI_그래프_엔지니어링_설계_정리.md), 전체 작업 순서와 진행 상태는 [프로젝트 로드맵](PROJECT_ROADMAP.md), 외부 공격 기준은 [탐지 기준 및 위협 정보 정책](docs/DETECTION_POLICY.md), 대응 제약은 [보안 및 대응 정책](docs/SECURITY.md)을 참고한다.
