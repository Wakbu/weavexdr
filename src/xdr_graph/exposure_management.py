from __future__ import annotations

import os
import platform
from collections import Counter
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Iterable

from xdr_graph.models import IncidentReport


def installed_software_inventory(limit: int = 200) -> list[dict[str, str]]:
    """Read Windows uninstall metadata without launching a shell or external scanner."""
    if os.name != "nt":
        return []
    import winreg

    roots = (
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    )
    items: dict[tuple[str, str], dict[str, str]] = {}
    for hive, path in roots:
        try:
            parent = winreg.OpenKey(hive, path)
        except OSError:
            continue
        with parent:
            try:
                key_count = winreg.QueryInfoKey(parent)[0]
            except OSError:
                continue
            for index in range(key_count):
                try:
                    key_name = winreg.EnumKey(parent, index)
                    child = winreg.OpenKey(parent, key_name)
                except OSError:
                    continue
                with child:
                    def value(name: str) -> str:
                        try:
                            return str(winreg.QueryValueEx(child, name)[0]).strip()
                        except OSError:
                            return ""

                    name = value("DisplayName")
                    if not name or value("SystemComponent") == "1":
                        continue
                    version, publisher = value("DisplayVersion"), value("Publisher")
                    items[(name.casefold(), version)] = {
                        "name": name,
                        "version": version or "버전 미확인",
                        "publisher": publisher or "게시자 미확인",
                    }
                    if len(items) >= limit:
                        break
        if len(items) >= limit:
            break
    return sorted(items.values(), key=lambda item: item["name"].casefold())[:limit]


def build_exposure_overview(
    reports: Iterable[IncidentReport],
    *,
    collector_status: dict[str, object],
    integrity_state: str,
    startup_active: bool,
    software: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    """Calculate transparent local posture findings; never claim online CVE coverage."""
    now, cutoff = datetime.now(UTC), datetime.now(UTC) - timedelta(days=30)
    selected = [
        report for report in reports
        if any(event.timestamp >= cutoff for event in report.source_events)
    ]
    software = installed_software_inventory() if software is None else software
    event_counts: Counter[str] = Counter()
    external_ips: Counter[str] = Counter()
    users: set[str] = set()
    for report in selected:
        for event in report.source_events:
            event_counts[event.event_type] += 1
            user = getattr(event, "user", None)
            if user:
                users.add(str(user))
            for field in ("destination_ip", "source_ip"):
                address = getattr(event, field, None)
                if address:
                    try:
                        if not ip_address(str(address)).is_private:
                            external_ips[str(address)] += 1
                    except ValueError:
                        # 정규화 계약 밖의 주소는 노출 점수에 임의 반영하지 않는다.
                        continue

    recommendations: list[dict[str, object]] = []

    def add(identifier: str, severity: str, title: str, evidence: str, remediation: str, category: str, penalty: int) -> None:
        recommendations.append({
            "id": identifier, "severity": severity, "title": title, "evidence": evidence,
            "remediation": remediation, "category": category, "penalty": penalty,
        })

    collector_state = str(collector_status.get("state", "not_configured"))
    if collector_state not in {"running", "protecting"}:
        add("collector-gap", "high", "실시간 수집 범위 확인 필요", f"현재 수집기 상태: {collector_state}", "운영 관리에서 Sysmon과 Windows 이벤트 수집 상태를 확인하세요.", "device", 22)
    if integrity_state != "healthy":
        add("integrity-gap", "critical", "자체 보호 기준과 다른 파일 발견", f"무결성 상태: {integrity_state}", "업데이트 직후가 아니라면 변경·누락 파일을 자체 보호 상세에서 확인하세요.", "device", 28)
    if not startup_active:
        add("startup-gap", "medium", "로그인 후 보호 자동 시작 꺼짐", "Windows 시작 프로그램이 비활성입니다.", "지속적인 보호가 필요하면 설정에서 자동 시작을 켜세요.", "device", 10)
    if not selected:
        add("telemetry-gap", "high", "최근 30일 분석 자료 없음", "최근 사건 또는 정규화 이벤트가 없습니다.", "수집기 권한·채널·마지막 정상 시각을 확인하세요.", "device", 18)
    if event_counts["remote_access"]:
        add("remote-surface", "medium", "원격 접속 활동 관찰", f"최근 30일 원격 접속 이벤트 {event_counts['remote_access']}건", "사용하지 않는 RDP·SMB·WinRM은 Windows 방화벽과 서비스 설정에서 제한하세요.", "network", 8)
    persistence_count = sum(event_counts[name] for name in ("registry_persistence", "service_install", "scheduled_task", "wmi_subscription"))
    if persistence_count:
        add("persistence-surface", "high", "지속성 변경 활동 관찰", f"최근 30일 지속성 관련 이벤트 {persistence_count}건", "위협 헌팅에서 해당 이벤트를 조사하고 승인된 설치인지 확인하세요.", "device", min(18, 8 + persistence_count))
    identity_count = event_counts["account_change"] + event_counts["privilege_use"]
    if identity_count:
        add("identity-surface", "medium", "계정·권한 변경 활동 관찰", f"계정 또는 권한 이벤트 {identity_count}건", "변경 사용자와 시간대를 엔터티 위험 분석에서 확인하세요.", "identity", min(12, 5 + identity_count))
    unknown_publishers = sum(item["publisher"] == "게시자 미확인" for item in software)
    if unknown_publishers:
        add("software-metadata", "low", "게시자 미확인 프로그램 존재", f"설치 프로그램 {len(software)}개 중 {unknown_publishers}개", "사용하지 않는 프로그램인지 확인하고 공식 설치본으로 업데이트하세요. CVE 판정에는 별도 오프라인 취약점 콘텐츠가 필요합니다.", "software", min(8, unknown_publishers))

    recommendations.sort(key=lambda item: ({"critical": 4, "high": 3, "medium": 2, "low": 1}[str(item["severity"])], int(item["penalty"])), reverse=True)
    secure_score = max(0, 100 - sum(int(item["penalty"]) for item in recommendations))
    breakdown = {
        category: max(0, 100 - sum(int(item["penalty"]) for item in recommendations if item["category"] == category))
        for category in ("device", "software", "identity", "network")
    }
    return {
        "secure_score": secure_score,
        "breakdown": breakdown,
        "recommendations": recommendations,
        "assets": {
            "device": {"name": platform.node() or "local-device", "os": platform.platform(), "criticality": "primary"},
            "software_count": len(software), "identity_count": len(users), "external_ip_count": len(external_ips),
        },
        "software": software,
        "signals": {
            "remote_access": event_counts["remote_access"], "persistence": persistence_count,
            "identity_changes": identity_count, "external_ips": external_ips.most_common(10),
        },
        "generated_at": now.isoformat(),
        "data_window_days": 30,
        "vulnerability_feed": "not_configured",
        "privacy": "local_only",
    }
