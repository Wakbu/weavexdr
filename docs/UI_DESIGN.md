# WeaveXDR UI 설계 기준

## 참고한 조사 흐름

- Microsoft Defender XDR: 사건 그래프에서 사용자, 장치, 프로세스, 파일과 IP를 연결하고 노드 선택 시 상세 정보를 연다.
- Palo Alto Cortex XDR: 원인 프로세스부터 후속 실행·파일·네트워크 행위를 인과관계 체인으로 보여준다.
- Bitdefender XDR: 활동 패널, 그래프, 엔티티 상세를 한 조사 흐름으로 묶고 진입점과 이탈 지점을 구분한다.
- Kaspersky XDR: 경보와 공통 엔티티의 관계를 조사 그래프로 표현한다.
- 알약 XDR: 엔드포인트·네트워크 등 여러 영역의 이벤트를 연결해 다단계 공격 전체 맥락을 제공한다.
- 사용자 learning-flow: 검색·범주 필터·연결선·선택 노드 상세 패널을 한 화면에 배치한다.

## 현재 시각 원칙

- 흑연색 기반의 중성 표면과 얇은 구분선을 사용하고 상태색은 위험·경고·정상 의미에만 쓴다.
- 둥근 카드와 장식용 그라데이션을 반복하지 않는다.
- 개요는 `신호 요약 → 공격 관계도/지도 → 추이 → 사건 큐` 순서로 읽힌다.
- 조사 화면은 `사건 헤더 → 관계도 → 선택 엔티티 → 위치/검증/출처` 순서를 유지한다.
- 네트워크 방향을 확인할 수 없는 이벤트는 유입으로 단정하지 않는다.
- GeoIP 데이터가 없는 주소는 임의 국가 대신 `GeoIP DB 미연동`으로 표시한다.

## 시각 검증 기준

- 기본 데스크톱, 900px, 640px 너비에서 본문 가로 넘침이 없어야 한다.
- 좁은 화면의 큰 그래프는 글자를 축소하지 않고 그래프 영역만 가로 스크롤한다.
- 페이지 전환 시 스크롤을 상단으로 복원한다.
- 텍스트 잘림, 패널 겹침, 비정상적인 빈 공간과 브라우저 오류를 실제 EXE에서 확인한다.
- 외부 사례의 화면을 그대로 복제하지 않고 정보 구조와 조사 흐름만 참고한다.

## 참고 링크

- <https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-graph>
- <https://docs-cortex.paloaltonetworks.com/r/Cortex-XDR/Cortex-XDR-3.x-Documentation/Causality-view>
- <https://www.bitdefender.com/business/support/en/77211-151142-investigating-incidents.html>
- <https://support.kaspersky.com/xdr-expert/1.2/264307>
- <https://blog.alyac.co.kr/5557>
- <https://wakbu.github.io/learning-flow/>
