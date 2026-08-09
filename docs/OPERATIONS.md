# WeaveXDR 운영·복구 안내

## Windows 설치

지원 기준은 Windows 11과 Python 3.11 이상이다. 관리자 PowerShell에서 32자 이상의 API 토큰과 16자 이상의 개인정보 salt를 시스템 환경 변수로 먼저 등록한다. 실제 값은 문서·설정·명령 기록에 남기지 않는다.

```powershell
[Environment]::SetEnvironmentVariable('WEAVEXDR_API_TOKEN', '<32자 이상>', 'Machine')
[Environment]::SetEnvironmentVariable('WEAVEXDR_PRIVACY_SALT', '<16자 이상>', 'Machine')
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

ZIP의 `WeaveXDR.exe`는 설치 없이 실행하는 로컬 대시보드 실행본이다. 소스 폴더에서는 프로젝트 루트의 동일한 파일 하나를 현재 버전으로 유지하고, 새 빌드가 완전히 성공한 뒤 기존 파일을 교체한다.

포터블 EXE는 실행할 때 임시 API 토큰을 자동 발급하고 브라우저에서 프로세스 전용 HttpOnly 세션으로 교환한다. 토큰 원문은 주소에서 즉시 제거되며 같은 브라우저의 새 탭은 별도 입력 없이 세션을 재사용한다. 전체 브라우저 세션이 끝났거나 인증 오류가 발생하면 EXE를 정상 종료한 뒤 다시 실행한다.

외부 API 클라이언트를 직접 사용할 때만 `WEAVEXDR_API_TOKEN`을 32자 이상으로 지정한다. 포터블 실행은 `User`, Windows 서비스는 `Machine` 환경 변수를 사용하며 토큰을 문서나 로그에 기록하지 않는다.

## Sysmon 실시간 수집

WeaveXDR는 Sysmon Operational 로그의 프로세스 생성(1), 네트워크 연결(3), 파일 생성(11)을 새 레코드부터 실시간 수집한다. 포터블 EXE가 `Sysmon 로그 읽기 권한 부족`을 표시하면 대시보드의 `수집 권한 설정` 버튼을 누른다. Windows UAC에서 허용하면 내장 스크립트가 실행되고 수집기가 자동 재연결되므로 사용자가 경로나 명령을 직접 입력할 필요가 없다.

수동 복구가 필요한 경우에만 압축 폴더의 다음 스크립트를 관리자 PowerShell에서 실행한다.

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\configure_sysmon_access.ps1
```

설정을 바꾸지 않고 관리자 권한·대상 사용자·기존 읽기 권한만 점검하려면 다음을 실행한다.

```powershell
.\configure_sysmon_access.ps1 -CheckOnly
```

스크립트는 현재 로그인 사용자에게 Sysmon 채널의 읽기 권한 `0x1`만 추가하고 기존 채널 SDDL을 `%ProgramData%\WeaveXDR`에 백업한다. 원상 복구는 다음과 같다.

```powershell
.\configure_sysmon_access.ps1 -Restore
```

Sysmon 자체가 없으면 먼저 Microsoft Sysmon을 설치하고 `config/sysmon-minimal.xml`과 동등하게 이벤트 ID 1·3·11이 기록되도록 구성해야 한다. 설치형 WeaveXDR 서비스는 LocalSystem 수집기를 사용하므로 별도의 사용자 채널 권한이 필요하지 않다.

## 대시보드 사용

- **보안 개요**: 전체 사건 수, 위험도 분포, 최근 사건과 수집 상태를 확인한다.
- **사건**: 검색과 판정 필터로 조사할 사건을 선택한다. 초기에는 `안전한 데모 생성`으로 화면 흐름을 확인할 수 있으며 실제 악성 코드를 실행하지 않는다.
- **조사**: 요약, 원본 증거, 시간순 공격 흐름과 권장 대응을 한 사건 단위로 확인한다.
- **설정**: Sysmon 수집 상태, 처리 이벤트 수, 마지막 수집 시각, 필요한 권한 조치와 API 세션 상태를 확인한다.

브라우저 탭만 닫으면 로컬 서버는 종료되지 않는다. 왼쪽 아래의 `WeaveXDR 종료`를 누르고 확인 대화상자에서 승인해야 EXE와 8765 포트가 함께 종료된다.

`install.ps1`은 `%ProgramFiles%\WeaveXDR`에 전용 가상환경과 wheel을 설치하고 `WeaveXDR` Windows 서비스를 자동 시작으로 등록한다. 서비스는 일반 분석·저장·loopback API를 제공한다. 방화벽 대응 등 관리자 조치는 기존 승인 및 재검증 정책을 별도로 통과해야 한다.

개발 PC에서는 서비스 등록을 자동 검증하지 않는다. 이는 관리자 권한과 시스템 변경을 수반하므로 실제 설치 대상에서 사용자가 설치 스크립트를 명시적으로 실행한다.

## 제거

```powershell
.\uninstall.ps1
```

기본 제거는 프로그램만 삭제하고 `%ProgramData%\WeaveXDR`의 사건 DB와 로그를 보존한다. 데이터까지 지우려면 복구가 불가능함을 확인한 뒤 `-RemoveData`를 명시한다.

## 로그와 디스크

서비스 로그는 `%ProgramData%\WeaveXDR\logs`에 UTF-8로 기록한다. 기본 파일당 10 MiB, 백업 5개로 회전하므로 로그 사용량은 약 60 MiB 이내다. 사건 DB와 격리 저장소는 별도의 보존 정책을 적용한다.

## 업데이트와 롤백

로컬 `dist`에는 확인과 롤백에 필요한 최신 Windows 릴리스 3개만 유지한다. 패키지 빌드가 새 ZIP 생성을 완료한 뒤 버전 번호를 기준으로 오래된 폴더와 ZIP을 정리하며, wheel과 GitHub에 게시된 릴리스는 이 정리 대상이 아니다.

빌드 검증은 운영 기본 포트 8765 대신 OS가 임시 배정한 loopback 포트를 사용한다. 따라서 사용 중인 WeaveXDR를 끄지 않고도 새 EXE의 health·대시보드·인증·정상 종료를 검사할 수 있으며, 일반 실행은 계속 8765를 사용한다.

업데이트는 다음 순서로 수행한다.

1. 릴리스 자산의 SHA-256을 게시 값과 비교한다.
2. 압축 경로 탈출을 검사한 뒤 설치 폴더와 같은 볼륨의 임시 폴더에 푼다.
3. 기존 설치 폴더 전체를 rollback 폴더로 이름 변경한다.
4. 새 버전을 원래 경로로 전환하고 서비스·health·대시보드를 확인한다.
5. 시작 또는 회귀 검사 실패 시 `rollback_update`로 기존 폴더를 되돌린다.

Windows 설치 ZIP은 신규 설치용이며 실행 중인 설치 폴더에 직접 덮어쓰지 않는다. 자동 업데이트 채널을 공개하기 전에는 서명된 런타임 전용 아카이브만 업데이트 관리자에 전달한다.

## 장애 복구

- API가 열리지 않으면 서비스 상태, `%ProgramData%\WeaveXDR\logs\weavexdr.log`, 시스템 환경 변수 존재를 순서대로 확인한다.
- 로컬 모델이 중단되면 규칙 기반 모델로 자동 대체된다. Ollama 복구 후 새 사건부터 다시 로컬 모델을 사용한다.
- 수집 저장 실패 시 메모리 버퍼는 배치를 유지하고 다음 flush에서 재시도한다.
- 감사 로그 무결성 검사가 실패하면 실제 대응을 중지하고 백업본과 비교한다.
- 격리 복원은 원래 경로와 해시를 재검증하고 사용자 확인 후 수행한다.
- DB 손상 시 서비스를 중지하고 원본 DB를 보존한 채 최신 백업으로 복구한다.

## 릴리스 후보 확인

`python -m pytest` 전체 통과, `python scripts/validate_release.py` 통과, 일반 모드 EXE의 health·dashboard·인증 API·종료 확인, 설치 ZIP 구성과 버전 형식, UTF-8 한국어/영어 표시, GitHub 릴리스 본문과 다운로드 자산을 확인한다.
