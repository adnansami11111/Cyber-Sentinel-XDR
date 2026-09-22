from app.detection.risk import calculate_risk_score


def test_low_risk():
    score = calculate_risk_score(
        severity="LOW",
        confidence=0.50,
    )

    assert score == 30


def test_high_confidence_bruteforce():
    score = calculate_risk_score(
        severity="HIGH",
        confidence=0.95,
        event_count=5,
    )

    assert score == 99


def test_malicious_source():
    score = calculate_risk_score(
        severity="HIGH",
        confidence=0.95,
        event_count=5,
        source_reputation="MALICIOUS",
    )

    assert score == 100


def test_score_never_exceeds_100():
    score = calculate_risk_score(
        severity="CRITICAL",
        confidence=1.0,
        event_count=100,
        source_reputation="MALICIOUS",
        asset_criticality="critical",
    )

    assert score == 100


def test_score_never_below_zero():
    score = calculate_risk_score(
        severity="LOW",
        confidence=0.0,
        source_reputation="BENIGN",
        asset_criticality="low",
    )

    assert score >= 0
