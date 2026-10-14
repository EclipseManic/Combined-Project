"""AbstractAPI must never exceed one request per second per product.

AbstractAPI sells three products, each with its own key, its own quota and its own
one-request-per-second allowance. The adapters declare that as
``minimum_interval_seconds=1.0``; this module proves the pipeline actually
*enforces* the declaration rather than merely recording it, and that the three
products are budgeted independently.
"""

import pytest

from app.backend.adapters.abstract_api import (
    AbstractAPIAdapter,
    AbstractAPIIPAdapter,
    AbstractAPIPhoneAdapter,
)
from app.backend.rate_limiter import RateLimiter

PRODUCTS = (AbstractAPIAdapter, AbstractAPIIPAdapter, AbstractAPIPhoneAdapter)


@pytest.mark.parametrize("cls", PRODUCTS, ids=lambda c: c.name)
def test_every_abstractapi_product_declares_one_request_per_second(cls):
    rate = cls().rate_limit
    assert rate.minimum_interval_seconds >= 1.0, (
        f"{cls.name} allows {rate.minimum_interval_seconds}s between requests; "
        "AbstractAPI permits one request per second per product."
    )


def test_each_product_has_its_own_name_so_they_budget_separately():
    # The limiter keys its schedule on adapter.name. Distinct names plus distinct
    # keys means one exhausted product cannot throttle the other two.
    names = {cls.name for cls in PRODUCTS}
    assert len(names) == 3
    assert names == {"AbstractAPI", "AbstractAPI IP", "AbstractAPI Phone"}


def test_a_second_request_to_the_same_product_is_pushed_out_by_a_second():
    limiter = RateLimiter()
    first = limiter.reserve_provider("AbstractAPI IP", 60, 100, minimum_interval=1.0, max_wait=30.0)
    assert first.granted

    second = limiter.reserve_provider("AbstractAPI IP", 60, 100, minimum_interval=1.0, max_wait=30.0)
    assert second.granted
    # The guarantee is on the slot times: the second send is scheduled a full
    # second after the first. wait_seconds is measured from a slightly later
    # "now", so it lands marginally under 1.0.
    assert second.slot_time - first.slot_time >= 1.0
    assert second.wait_seconds > 0.9


def test_a_slow_wait_beyond_the_deadline_is_refused_rather_than_queued():
    # max_wait is the caller's remaining IOC budget. When the required gap does
    # not fit, the caller must be told to retry rather than block the pipeline.
    limiter = RateLimiter()
    limiter.reserve_provider("AbstractAPI", 60, 100, minimum_interval=1.0, max_wait=30.0)
    refused = limiter.reserve_provider("AbstractAPI", 60, 100, minimum_interval=1.0, max_wait=0.2)
    assert not refused.granted
    assert refused.retry_after_seconds >= 1.0


def test_the_three_products_do_not_block_each_other():
    limiter = RateLimiter()
    limiter.reserve_provider("AbstractAPI", 60, 100, minimum_interval=1.0, max_wait=30.0)
    # A different product with its own key is not delayed by the first.
    other = limiter.reserve_provider("AbstractAPI Phone", 60, 100, minimum_interval=1.0, max_wait=30.0)
    assert other.granted
    assert other.wait_seconds == pytest.approx(0.0, abs=0.05)


def test_daily_quota_is_tracked_per_product_too():
    # 100 requests/month on the free tier; hitting it must stop further sends
    # rather than erroring one by one. requests_per_minute is raised above 100
    # so the minute window is not the binding constraint and the daily cap is
    # what is actually being exercised.
    limiter = RateLimiter()
    granted = sum(
        1
        for _ in range(101)
        if limiter.reserve_provider(
            "AbstractAPI Phone", 200, 100, minimum_interval=0.0, max_wait=0.0
        ).granted
    )
    assert granted == 100
    exhausted = limiter.reserve_provider("AbstractAPI Phone", 200, 100, minimum_interval=0.0, max_wait=0.0)
    assert not exhausted.granted
    assert exhausted.reason == "daily_quota_exhausted"
    # A different product is unaffected by that exhaustion.
    assert limiter.reserve_provider("AbstractAPI IP", 200, 100, minimum_interval=0.0, max_wait=0.0).granted


def test_ipquality_is_not_confined_to_one_per_second():
    # A guard against copy-pasting the AbstractAPI limit onto a provider with a
    # much higher allowance.
    from app.backend.adapters.ipquality import (
        IPQualityEmailAdapter,
        IPQualityIPAdapter,
        IPQualityPhoneAdapter,
    )

    for cls in (IPQualityPhoneAdapter, IPQualityIPAdapter, IPQualityEmailAdapter):
        assert cls().rate_limit.minimum_interval_seconds < 1.0
