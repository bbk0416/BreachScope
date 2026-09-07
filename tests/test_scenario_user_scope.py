from __future__ import annotations

from types import SimpleNamespace

from breachscope import scenario


def _event(host: str, user: str | None, session: str | None = None):
    return SimpleNamespace(
        host=host,
        user=user,
        raw={
            "canonical": {
                "host": {"name": host},
                "session": {"id": session},
            },
            "SubjectLogonId": session,
        },
    )


def _chain(host: str, user: str | None, session: str | None = None):
    return SimpleNamespace(
        chain_type="activity",
        events=[_event(host, user, session)],
    )


def _finding(host: str, user: str | None, session: str | None = None):
    return SimpleNamespace(event=_event(host, user, session))


def _raw_session_event(
    host: str,
    user: str | None,
    *,
    target: str | None = None,
    subject: str | None = None,
):
    raw = {"canonical": {"host": {"name": host}}}
    if target is not None:
        raw["TargetLogonId"] = target
    if subject is not None:
        raw["SubjectLogonId"] = subject
    return SimpleNamespace(host=host, user=user, raw=raw)


def _raw_session_chain(
    host: str,
    user: str | None,
    *,
    target: str | None = None,
    subject: str | None = None,
):
    return SimpleNamespace(
        chain_type="session",
        events=[
            _raw_session_event(
                host,
                user,
                target=target,
                subject=subject,
            )
        ],
    )


def test_scenario_scope_tracks_user_identity():
    scope = scenario._bs_p005_scope(_chain("HOST-A", "CORP\\Alice"))

    assert scope["hosts"] == {"host-a"}
    assert scope["users"] == {"corp\\alice"}
    assert scope["sessions"] == set()


def test_same_host_different_users_are_separate_components_without_session():
    alice = _chain("HOST-A", "alice")
    bob = _chain("HOST-A", "bob")

    groups = scenario._bs_p005_partition_chains([alice, bob])

    assert len(groups) == 2


def test_same_host_same_user_stays_in_one_component_without_session():
    first = _chain("HOST-A", "alice")
    second = _chain("HOST-A", "ALICE")

    groups = scenario._bs_p005_partition_chains([first, second])

    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_host_only_chain_cannot_bridge_different_user_components():
    alice = _chain("HOST-A", "alice")
    host_only = _chain("HOST-A", None)
    bob = _chain("HOST-A", "bob")

    groups = scenario._bs_p005_partition_chains([alice, host_only, bob])

    assert len(groups) == 3


def test_other_user_finding_cannot_strengthen_user_scoped_component():
    component = scenario._bs_p005_component_scope([_chain("HOST-A", "alice")])
    findings = [
        _finding("HOST-A", "alice"),
        _finding("HOST-A", "bob"),
    ]

    selected = scenario._bs_p005_filter_findings(findings, component)

    assert len(selected) == 1
    assert scenario._bs_p005_scope(selected[0])["users"] == {"alice"}


def test_same_session_id_on_different_hosts_stays_separate():
    first = _chain("HOST-A", "alice", "0x1234")
    second = _chain("HOST-B", "alice", "0x1234")

    groups = scenario._bs_p005_partition_chains([first, second])

    assert len(groups) == 2


def test_same_session_id_on_same_host_stays_together():
    first = _chain("HOST-A", "alice", "0x1234")
    second = _chain("HOST-A", "ALICE", "0x1234")

    groups = scenario._bs_p005_partition_chains([first, second])

    assert len(groups) == 1
    assert len(groups[0]) == 2


def test_other_host_finding_with_same_session_id_is_excluded():
    component = scenario._bs_p005_component_scope(
        [_chain("HOST-A", "alice", "0x1234")]
    )
    findings = [
        _finding("HOST-A", "alice", "0x1234"),
        _finding("HOST-B", "alice", "0x1234"),
    ]

    selected = scenario._bs_p005_filter_findings(findings, component)

    assert len(selected) == 1
    assert scenario._bs_p005_scope(selected[0])["hosts"] == {"host-a"}


def test_target_logon_id_is_authoritative_over_subject_logon_id():
    event = _raw_session_event(
        "HOST-A",
        "alice",
        target="0x2222",
        subject="0x1111",
    )

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == {"0x2222"}


def test_subject_logon_id_alone_does_not_define_scenario_session():
    event = _raw_session_event(
        "HOST-A",
        "alice",
        subject="0x1111",
    )

    event_scope = scenario._bs_p005_scope(event)

    assert event_scope["sessions"] == set()


def test_subject_logon_id_cannot_bridge_distinct_target_sessions():
    first = _raw_session_chain(
        "HOST-A",
        "alice",
        target="0x2222",
        subject="0x1111",
    )
    second = _raw_session_chain(
        "HOST-A",
        "alice",
        target="0x3333",
        subject="0x2222",
    )

    groups = scenario._bs_p005_partition_chains([first, second])

    assert len(groups) == 2
