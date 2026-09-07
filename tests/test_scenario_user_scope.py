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
