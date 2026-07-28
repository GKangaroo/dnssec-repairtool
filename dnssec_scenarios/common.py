from dataclasses import dataclass, field
from typing import Callable


Hook = Callable[[object], None]
ZoneHook = Callable[[object, str], None]
SignArgsHook = Callable[[object, str], list[str] | None]


@dataclass(frozen=True)
class Scenario:
    name: str
    description: str
    expected_codes: tuple[str, ...]
    fix_message: str
    qname: str = "www.example.com."
    rrtypes: str | None = None
    corrupt_child_ds: bool = False
    include_example_ds: bool = True
    example_ttl: int = 300
    extra_example_records: tuple[str, ...] = field(default_factory=tuple)
    before_write: Hook | None = None
    before_sign: Hook | None = None
    sign_args: SignArgsHook | None = None
    after_sign_zone: ZoneHook | None = None
    after_trusted_keys: Hook | None = None
    before_fix: Hook | None = None
