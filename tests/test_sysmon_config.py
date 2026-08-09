from pathlib import Path
from xml.etree import ElementTree


SYSMON_CONFIG = Path(__file__).parents[1] / "config" / "sysmon-minimal.xml"


def load_sysmon_root():
    # 실제 배포 파일을 파싱해 XML 문법 오류와 핵심 설정의 우발적 삭제를 함께 검사한다.
    return ElementTree.parse(SYSMON_CONFIG).getroot()


def test_sysmon_config_uses_the_installed_schema_and_hashes():
    root = load_sysmon_root()

    assert root.tag == "Sysmon"
    assert root.attrib["schemaversion"] == "4.91"
    assert root.findtext("HashAlgorithms") == "SHA256,IMPHASH"


def test_sysmon_config_collects_the_required_event_types():
    event_filtering = load_sysmon_root().find("EventFiltering")
    assert event_filtering is not None

    # 현재 수집·파서 로드맵의 직접 입력인 Event ID 1, 3, 11이 모두 존재해야 한다.
    assert event_filtering.find("ProcessCreate") is not None
    assert event_filtering.find("NetworkConnect") is not None
    assert event_filtering.find("FileCreate") is not None

    network_images = {
        rule.text for rule in event_filtering.findall("NetworkConnect/Image")
    }
    assert "\\powershell.exe" in network_images
    assert "\\pwsh.exe" in network_images

    file_extensions = {
        rule.text for rule in event_filtering.findall("FileCreate/TargetFilename")
    }
    assert {".exe", ".dll", ".ps1", ".vbs"} <= file_extensions
