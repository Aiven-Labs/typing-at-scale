from dataclasses import dataclass


@dataclass
class SomeItem:
    a: int
    b: str


# x = SomeItem("a", "asd")
# print(x.a, type(x.a))