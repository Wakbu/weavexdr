# WeaveXDR

WeaveXDR은 Windows 개인 PC를 위한 로컬 AI XDR 프로젝트다. 보안 이벤트와 파일·프로세스·네트워크 증거를 실행 그래프로 분석하고, 규칙 기반 검증과 선택적 Ollama 모델을 함께 사용한다.

## 주요 기능

- Sysmon 프로세스·네트워크·파일 이벤트 정규화와 사건 상관분석
- SHA-256, Authenticode, YARA와 Microsoft Defender 기반 파일 검사
- OWASP, MITRE ATT&CK와 CISA 기준 탐지 규칙
- 규칙 모델 장애 대체와 정책 가드가 적용된 선택적 로컬 모델
- 승인·대상 재검증 기반 프로세스 종료, 파일 격리·복원과 네트워크 차단
- 인증된 loopback API, HttpOnly 브라우저 세션, Sysmon 실시간 사건 대시보드와 감사 로그
- SQLite 보안 지식 그래프 기반 유사 사건과 공격 경로 조회

## 빠른 실행

일반 사용자는 릴리스 ZIP을 내려받아 압축을 풀고 `WeaveXDR.exe`만 실행한다. 별도 인증 정보를 만들거나 입력할 필요가 없다. 브라우저가 자동으로 열리지 않으면 EXE를 종료한 뒤 다시 실행하며, 주소창에서 대시보드 주소를 먼저 직접 열지 않는다.

EXE는 실행할 때마다 임시 인증 정보를 자동 생성해 브라우저 보안 세션으로 바꾼다. 이 과정은 사용자 입력 없이 처리되며 설정 화면에도 인증 입력란을 표시하지 않는다. 자세한 복구 절차는 [운영·복구 안내](docs/OPERATIONS.md#일반-사용자의-인증-절차)를 참고한다.

로컬 빌드에서는 프로젝트 루트의 `WeaveXDR.exe`가 현재 실행본이다. 이 실행 파일은 소스 Git에 포함하지 않고 릴리스 자산으로만 배포한다.

## 개발 환경

Python 3.11 이상이 필요하다.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest -q
```

현재 회귀 테스트는 `127 passed`, 기준 평가 데이터는 `30/30 passed`다.

## 문서

- [시스템 아키텍처](docs/ARCHITECTURE.md)
- [탐지 정책](docs/DETECTION_POLICY.md)
- [보안 및 대응 정책](docs/SECURITY.md)
- [개발과 품질 검증](docs/DEVELOPMENT.md)
- [설치·운영·복구](docs/OPERATIONS.md)

## 안전 원칙

AI 판단만으로 파일을 영구 삭제하지 않는다. 실제 대응은 사용자 승인, 대상 재검증과 시스템 보호 정책을 통과해야 한다. API와 대시보드는 기본적으로 `127.0.0.1`에만 노출한다.
