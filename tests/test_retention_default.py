"""Retention defaults to 14 days since v2.5.0 (was 7): the predictor learns
from IPs that leave and return, and a purged row returns with no history.
The shipped config and the code fallback must agree, or a published image
(config baked in) and a source run would keep entries for different spans."""
import os

import yaml

from threatfeedme import pipeline
from threatfeedme.database import Database

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_shipped_config_and_fallback_agree_on_14_days():
    with open(os.path.join(REPO, "config.yaml")) as f:
        shipped = yaml.safe_load(f)["retention"]["max_age_days"]
    assert shipped == pipeline.DEFAULT_RETENTION_DAYS == 14


def test_fallback_applies_when_nothing_is_set(tmp_path):
    db = Database(str(tmp_path / "t.db"))
    assert pipeline.retention_max_age_days(db, {}) == 14
    db.set_setting(pipeline.RETENTION_MAX_AGE_KEY, 7)        # an operator's saved value wins
    assert pipeline.retention_max_age_days(db, {"retention": {"max_age_days": 14}}) == 7
