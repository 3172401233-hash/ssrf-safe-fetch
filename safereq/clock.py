"""Monotonic clock abstraction used for deadline enforcement."""

from __future__ import annotations

import time
from typing import Callable, Protocol


class Clock(Protocol):
    def now(self) -> float:
        """Return a monotonically increasing time in fractional seconds."""


class MonotonicClock:
    def __init__(self, func: Callable[[], float] = time.monotonic) -> None:
        self._func = func

    def now(self) -> float:
        return self._func()
