from nyctala.ingest.limits import RateLimiter


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_burst_then_refill() -> None:
    clock = Clock()
    limiter = RateLimiter(rate=1.0, burst=3, clock=clock)
    assert [limiter.hit("a") for _ in range(4)] == [True, True, True, False]
    assert limiter.retry_after("a") == 1
    clock.now = 1.0
    assert limiter.hit("a")
    assert not limiter.hit("a")


def test_keys_are_independent() -> None:
    limiter = RateLimiter(rate=1.0, burst=1, clock=Clock())
    assert limiter.hit("a")
    assert not limiter.hit("a")
    assert limiter.hit("b")


def test_allowed_does_not_spend() -> None:
    limiter = RateLimiter(rate=1.0, burst=1, clock=Clock())
    assert limiter.allowed("a")
    assert limiter.allowed("a")
    assert limiter.hit("a")
    assert not limiter.allowed("a")


def test_memory_is_bounded() -> None:
    limiter = RateLimiter(rate=0.001, burst=1, clock=Clock(), max_keys=100)
    for i in range(1000):
        limiter.hit(f"ip-{i}")
    assert len(limiter._buckets) <= 100
