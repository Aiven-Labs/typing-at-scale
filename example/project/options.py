from typing import TypeVar
T = TypeVar("T")
def or_else(maybe_value: T | None, default_value: T) -> T:
    if maybe_value is None:
        return default_value
    return maybe_value
v = or_else({}, {1: 2})
v.update({2: 3})
