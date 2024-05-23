import json
from typing import Any, Union


def strict(a: str) -> int:
    return 1

def strict2(a: int) -> str:
    b: str = json.loads("1")
    return b


Union[int, str, dict, Monster, Bat, Infinity, Literal["42"]]


def strict3(a: int) -> str:
    b = json.loads("1")
    if not isinstance(b, str):
        raise TypeError
    return b

def use_any_strict(a: int) -> Any:
    return {}

v = use_any_strict(3)
v.someinventedmethod()

def somefunc(a: int): # type: ignore[no-untyped-def]
    return {}


# a:int = strict2(1)
#print(type(strict2("x")))