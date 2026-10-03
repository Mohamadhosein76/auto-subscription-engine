import pytest

from auto_subscription_engine.core.verification import VerificationPolicy


def test_policy_requires_a_required_target():
    with pytest.raises(ValueError):
        VerificationPolicy.from_mapping({
            "targets": [{"url": "https://example.com", "required": False}],
        })


def test_policy_rejects_impossible_quorum():
    with pytest.raises(ValueError):
        VerificationPolicy.from_mapping({
            "repetitions": 1,
            "min_success_count": 2,
            "targets": [{"url": "https://example.com"}],
        })


def test_optional_target_not_counted_in_quorum_capacity():
    policy = VerificationPolicy.from_mapping({
        "repetitions": 2,
        "min_success_count": 2,
        "targets": [
            {"url": "https://required.example"},
            {"url": "https://optional.example", "required": False},
        ],
    })
    assert policy.min_success_count == 2
    assert len(policy.targets) == 2
