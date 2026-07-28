from .common import Scenario


scenario = Scenario(
    name="cname-loop",
    description="在子区构造两个互相指向的 CNAME。",
    expected_codes=("CNAME_LOOP",),
    qname="loop1.example.com.",
    rrtypes="A,CNAME",
    extra_example_records=(
        "loop1 IN CNAME loop2.example.com.",
        "loop2 IN CNAME loop1.example.com.",
    ),
    fix_message="fixing CNAME loop by replacing the cyclic aliases with a terminal address or a non-cyclic alias chain.",
)
