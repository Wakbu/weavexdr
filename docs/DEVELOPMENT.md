# 개발과 품질 검증

## 기본 검사

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -q -p no:cacheprovider tests
python scripts/validate_release.py
```

회귀 묶음은 실행 그래프, 로컬 모델 규칙 대체, Sysmon 실시간 수집 작업자, 수집 버퍼 재시도, 파일 검사 오류, 대응 실패·복구, API 토큰의 HttpOnly 세션 교환, 지식 그래프와 장기 반복 입력을 포함한다. 반복 입력 검사는 공유 엔티티가 중복 노드로 증가하지 않고 250개 사건을 제한 시간 안에 처리하는지 확인한다.

장시간 운영 증적은 `python scripts/run_operational_matrix.py --duration-seconds 86400 --sample-seconds 60 --output artifacts/soak-24h.json`처럼 생성한다. 7일 검사는 시간을 `604800`으로 바꾼다. 이 하네스의 구현·단기 회귀 통과와 실제 24시간·7일 Windows VM 완료 증적은 별도 상태로 관리한다.

릴리스 공급망 검사는 CI의 `pip-audit`와 `scripts/generate_supply_chain_report.py`가 담당한다. 코드 서명 인증서가 준비된 환경에서는 `WEAVEXDR_SIGNING_THUMBPRINT`를 설정하고 `scripts/sign_windows_release.ps1`을 사용한다.

## 실행 권한과 비밀

분석과 대시보드는 일반 사용자 권한으로 실행한다. 실제 대응은 기본 비활성화하며 방화벽·서비스 작업만 별도 관리자 작업자로 분리한다. API 토큰과 지식 그래프 개인정보 salt는 각각 `WEAVEXDR_API_TOKEN`, `WEAVEXDR_PRIVACY_SALT` 환경 변수로만 전달하며 설정 파일이나 로그에 기록하지 않는다.

릴리스 검증기는 JSON 구문, 위험 대응의 승인 강제, 설정 내 비밀 필드, 필수 문서 존재와 UTF-8 디코딩을 검사한다.

`scripts/build_local_executable.ps1`은 PyInstaller 빌드가 성공한 뒤 프로젝트 루트의 `WeaveXDR.exe`를 새 버전으로 교체한다. 번들 스모크 테스트는 Uvicorn 서버를 실제로 시작해 `/health`와 `/dashboard`가 모두 HTTP 200으로 응답하는지 확인한다. 이어서 일반 실행 모드 EXE를 다시 시작하고 인증 `/status`, `/shutdown`, 프로세스 종료까지 확인한다. 실행 파일과 내부 작업용 Markdown은 `.gitignore`로 제외하며, 공개 릴리스에는 설치 파일 또는 ZIP 자산으로만 첨부한다.

정식 릴리스 지정 전에는 스모크 모드뿐 아니라 일반 실행 모드의 EXE를 별도 프로세스로 시작해 같은 두 URL을 다시 확인한다. GitHub 릴리스 설명은 한국어·영어를 병기하고 주요 변경, 검증, 다운로드와 체크섬을 Markdown 헤더로 구분한다.

PyInstaller 빌드에는 문자열로 로드되는 Uvicorn 하위 모듈과 FastAPI 동기 엔드포인트가 사용하는 `anyio._backends`를 명시적으로 포함한다. 창 없는 EXE는 직접 호출하지 않고 프로세스 종료를 기다려 스모크 테스트의 실제 exit code를 확인한다.

## GitHub CLI 인증 유지

브라우저 로그인을 Windows 자격 증명 관리자에 저장하고 Git이 같은 인증을 사용하게 한다.

```powershell
gh auth login -h github.com -p https -w
gh auth setup-git
gh auth status
```

사용자 환경 변수 `GH_TOKEN`이 만료 토큰으로 남아 있으면 저장된 로그인을 덮어쓴다. `gh auth status`에 환경 변수 토큰이 표시될 때만 다음 명령으로 제거하고 새 터미널을 연다.

```powershell
[Environment]::SetEnvironmentVariable('GH_TOKEN', $null, 'User')
Remove-Item Env:GH_TOKEN -ErrorAction SilentlyContinue
```

릴리스 안정성 검사는 짧은 반복부터 24시간·7일 실행까지 같은 하네스를 사용한다.

```powershell
python scripts/run_soak_test.py --duration-seconds 60
python scripts/run_soak_test.py --duration-seconds 86400
```

## 로컬 모델 회귀 평가

동일한 평가 데이터로 모델별 정확도·오탐·미탐·P95 지연을 저장하고 다음 후보를 기준 결과와 비교한다.

```powershell
python -m xdr_graph.benchmark evaluations/baseline_cases.json --model qwen3:4b --output build/model-qwen3-4b.json
python -m xdr_graph.benchmark evaluations/baseline_cases.json --model qwen3:8b --baseline build/model-qwen3-4b.json --output build/model-qwen3-8b.json
```

그래프 검색 실험은 키워드 검색과 공유 엔티티 검색의 recall·평균 지연을 함께 기록한다. 생성형 GraphRAG는 그래프 검색이 정확도를 높이고 로컬 지연 한도를 통과한 경우에만 후보로 취급한다. 장기 그래프 기억은 저장소를 열 때 판정별 기본 보존 기간(정상 30일, 검토 90일, 고위험 180일)을 적용한다.
