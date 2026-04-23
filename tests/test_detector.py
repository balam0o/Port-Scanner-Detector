from detector import detect_vertical_scans


def test_detect_vertical_scan():
    connections = [
        {
            "timestamp": __import__("datetime").datetime.fromisoformat(f"2026-04-20T10:00:0{i}+00:00"),
            "source_ip": "192.168.1.50",
            "target_ip": "192.168.1.10",
            "target_port": port,
        }
        for i, port in enumerate([22, 23, 25, 53, 80], start=1)
    ]

    alerts = detect_vertical_scans(connections, window_seconds=60, threshold=5)

    assert len(alerts) == 1
    assert alerts[0]["type"] == "vertical_port_scan"
    assert alerts[0]["source_ip"] == "192.168.1.50"
    assert alerts[0]["target_ip"] == "192.168.1.10"
    assert alerts[0]["unique_ports"] == 5


def test_no_alert_when_below_threshold():
    connections = [
        {
            "timestamp": __import__("datetime").datetime.fromisoformat(f"2026-04-20T10:00:0{i}+00:00"),
            "source_ip": "192.168.1.50",
            "target_ip": "192.168.1.10",
            "target_port": port,
        }
        for i, port in enumerate([22, 23, 25, 53], start=1)
    ]

    alerts = detect_vertical_scans(connections, window_seconds=60, threshold=5)

    assert alerts == []