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

`scripts/build_local_executable.ps1`은 PyInstaller 빌드가 성공한 뒤 프로젝트 루트의 `WeaveXDR.exe`를 새 버전으로 교체한다. 실행 파일과 내부 작업용 Markdown은 `.gitignore`로 제외하며, 공개 릴리스에는 설치 파일 또는 ZIP 자산으로만 첨부한다.
