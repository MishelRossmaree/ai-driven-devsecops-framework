import pandas as pd
import pytest


@pytest.fixture()
def empty_df():
    return pd.DataFrame()


@pytest.fixture()
def clean_commit_df():
    """Single LOW-risk row – represents a healthy ML1 output."""
    return pd.DataFrame([
        {"risk_level": "LOW", "file_path": "src/foo.py", "risk_score": 0.1},
    ])


@pytest.fixture()
def clean_alert_df():
    """Single LOW-priority alert – represents a healthy ML2 output."""
    return pd.DataFrame([
        {
            "priority": "LOW",
            "tool": "cppcheck",
            "file": "src/foo.c",
            "line": 10,
            "alert_id": "A1",
            "message": "test message",
        }
    ])


@pytest.fixture()
def clean_anomaly_df():
    """NORMAL anomaly status – represents a healthy ML3 output."""
    return pd.DataFrame([
        {
            "anomaly_status": "NORMAL",
            "anomaly_score": -0.1,
            "reason": "Pipeline behaviour is normal",
        }
    ])
