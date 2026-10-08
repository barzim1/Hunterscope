import pytest

from helpers import ts
from hunterscope.detect import run_detections
from hunterscope.ingest.parsers import parse_windows
from hunterscope.models import Event

LSASS = "C:\\Windows\\System32\\lsass.exe"


def access(src, mask, target=LSASS, host="ws1", when=None) -> Event:
    return Event(ts=when or ts(2, 9, 0), source="windows", action="process_access", outcome="success",
                 host=host, app=src, detail={"target_image": target, "granted_access": mask, "call_trace": ""})


def fired(cfg, events):
    return [f for f in run_detections(events, cfg) if f.rule_id == "lsass_access"]


def test_parse_sysmon_10():
    e = parse_windows({"EventID": 10, "UtcTime": "2026-03-01 10:00:00.1", "Hostname": "ws1",
                       "SourceImage": "C:\\x\\a.exe", "TargetImage": LSASS, "GrantedAccess": "0x1410",
                       "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9d4c4|UNKNOWN(1)", "SourceUser": "D\\u"})
    assert (e.action, e.app, e.user) == ("process_access", "C:\\x\\a.exe", "D\\u")
    assert e.detail["target_image"] == LSASS and e.detail["granted_access"] == "0x1410"


@pytest.mark.parametrize("mask", ["0x1410", "0x1fffff", "0x1f3fff", "0X10"])
def test_memory_read_access_by_unknown_process_fires(cfg, mask):
    [f] = fired(cfg, [access("C:\\Users\\Public\\dump.exe", mask)])
    assert f.mitre == ["T1003.001"] and ("process", "C:\\Users\\Public\\dump.exe") in f.iocs


@pytest.mark.parametrize("mask", ["0x1000", "0x1400", "0x3000", "0x2000", "0x101400", "0x0"])
def test_access_without_vm_read_is_ignored(cfg, mask):
    assert fired(cfg, [access("C:\\Windows\\System32\\vboxservice.exe", mask)]) == []


@pytest.mark.parametrize(
    "src",
    [
        "C:\\Windows\\System32\\csrss.exe",
        "C:\\Windows\\System32\\wininit.exe",
        "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.2008.9-0\\MsMpEng.exe",
        "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
        "C:\\Program Files\\VMware\\VMware Tools\\vmtoolsd.exe",
        "C:\\WindowsAzure\\GuestAgent_2.7\\CollectGuestLogs.exe",
    ],
)
def test_allowlisted_sources_are_ignored(cfg, src):
    assert fired(cfg, [access(src, "0x1410")]) == []


def test_allowlist_is_path_aware_not_name_only(cfg):
    assert len(fired(cfg, [access("C:\\Users\\Public\\csrss.exe", "0x1410")])) == 1


def test_other_targets_are_ignored(cfg):
    assert fired(cfg, [access("C:\\x\\a.exe", "0x1410", target="C:\\Windows\\System32\\notlsass.exe")]) == []
    assert fired(cfg, [access("C:\\x\\a.exe", "0x1410", target="")]) == []


def test_bad_mask_does_not_crash(cfg):
    assert fired(cfg, [access("C:\\x\\a.exe", "garbage"), access("C:\\x\\a.exe", "")]) == []


def test_one_finding_per_host_and_source(cfg):
    evs = [access("C:\\x\\a.exe", "0x1410", when=ts(2, 9, i)) for i in range(20)]
    evs += [access("C:\\x\\a.exe", "0x1fffff", host="ws2"), access("C:\\x\\b.exe", "0x1410")]
    found = fired(cfg, evs)
    assert len(found) == 3
    first = next(f for f in found if len(f.evidence) == 20)
    assert "20 time(s)" in first.description and "0x1410" in first.description


def test_rule_can_be_disabled(cfg):
    import copy

    c = copy.deepcopy(cfg)
    c["rules"]["lsass_access"]["enabled"] = False
    assert fired(c, [access("C:\\x\\a.exe", "0x1410")]) == []
