import pytest

from scanner import parse_targets


def test_parse_localhost_in_safe_mode():
    targets = parse_targets(
        "127.0.0.1",
        safe=True,
        allow_public=False,
        max_targets_from_cidr=16,
    )

    assert targets == ["127.0.0.1"]


def test_parse_private_ip_in_safe_mode():
    targets = parse_targets(
        "192.168.1.10",
        safe=True,
        allow_public=False,
        max_targets_from_cidr=16,
    )

    assert targets == ["192.168.1.10"]


def test_reject_public_ip_in_safe_mode():
    with pytest.raises(ValueError):
        parse_targets(
            "8.8.8.8",
            safe=True,
            allow_public=False,
            max_targets_from_cidr=16,
        )


def test_allow_public_ip_when_explicitly_enabled():
    targets = parse_targets(
        "8.8.8.8",
        safe=True,
        allow_public=True,
        max_targets_from_cidr=16,
    )

    assert targets == ["8.8.8.8"]


def test_parse_small_private_cidr_in_safe_mode():
    targets = parse_targets(
        "192.168.1.0/30",
        safe=True,
        allow_public=False,
        max_targets_from_cidr=16,
    )

    assert targets == ["192.168.1.1", "192.168.1.2"]


def test_reject_large_cidr_in_safe_mode():
    with pytest.raises(ValueError):
        parse_targets(
            "192.168.1.0/24",
            safe=True,
            allow_public=False,
            max_targets_from_cidr=16,
        )


def test_empty_target_spec_fails():
    with pytest.raises(ValueError):
        parse_targets(
            "",
            safe=True,
            allow_public=False,
            max_targets_from_cidr=16,
        )