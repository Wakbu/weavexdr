# 개발과 품질 검증

## 기본 검사

```powershell
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD='1'
python -m pytest -q -p no:cacheprovider tests
python scripts/validate_release.py
```

회귀 묶음은 실행 그래프, 로컬 모델 규칙 대체, 수집 버퍼 재시도, 파일 검사 오류, 대응 실패·복구, API 인증, 지식 그래프와 장기 반복 입력을 포함한다. 반복 입력 검사는 공유 엔티티가 중복 노드로 증가하지 않고 250개 사건을 제한 시간 안에 처리하는지 확인한다.

## 실행 권한과 비밀

분석과 대시보드는 일반 사용자 권한으로 실행한다. 실제 대응은 기본 비활성화하며 방화벽·서비스 작업만 별도 관리자 작업자로 분리한다. API 토큰과 지식 그래프 개인정보 salt는 각각 `WEAVEXDR_API_TOKEN`, `WEAVEXDR_PRIVACY_SALT` 환경 변수로만 전달하며 설정 파일이나 로그에 기록하지 않는다.

릴리스 검증기는 JSON 구문, 위험 대응의 승인 강제, 설정 내 비밀 필드, 필수 문서 존재와 UTF-8 디코딩을 검사한다.

`scripts/build_local_executable.ps1`은 PyInstaller 빌드가 성공한 뒤 프로젝트 루트의 `WeaveXDR.exe`를 새 버전으로 교체한다. 번들 스모크 테스트는 Uvicorn 서버를 실제로 시작해 `/health`와 `/dashboard`가 모두 HTTP 200으로 응답하는지 확인한다. 실행 파일과 내부 작업용 Markdown은 `.gitignore`로 제외하며, 공개 릴리스에는 설치 파일 또는 ZIP 자산으로만 첨부한다.

정식 릴리스 지정 전에는 스모크 모드뿐 아니라 일반 실행 모드의 EXE를 별도 프로세스로 시작해 같은 두 URL을 다시 확인한다. GitHub 릴리스 설명은 한국어·영어를 병기하고 주요 변경, 검증, 다운로드와 체크섬을 Markdown 헤더로 구분한다.

PyInstaller 빌드에는 문자열로 로드되는 Uvicorn 하위 모듈과 FastAPI 동기 엔드포인트가 사용하는 `anyio._backends`를 명시적으로 포함한다. 창 없는 EXE는 직접 호출하지 않고 프로세스 종료를 기다려 스모크 테스트의 실제 exit code를 확인한다.
