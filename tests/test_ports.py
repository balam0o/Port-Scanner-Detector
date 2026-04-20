import pytest

from scanner import parse_ports


def test_parse_single_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]


def test_parse_port_range():
    assert parse_ports("80-82") == [80, 81, 82]


def test_parse_mixed_ports():
    assert parse_ports("22,80-82,443") == [22, 80, 81, 82, 443]


def test_parse_duplicate_ports():
    assert parse_ports("80,80,443") == [80, 443]


def test_empty_port_spec_fails():
    with pytest.raises(ValueError):
        parse_ports("")


def test_invalid_low_port_fails():
    with pytest.raises(ValueError):
        parse_ports("0")


def test_invalid_high_port_fails():
    with pytest.raises(ValueError):
        parse_ports("65536")


def test_invalid_range_fails():
    with pytest.raises(ValueError):
        parse_ports("100-80")


def test_invalid_text_port_fails():
    with pytest.raises(ValueError):
        parse_ports("abc")