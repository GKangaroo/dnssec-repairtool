from .common import Scenario


scenario = Scenario(
    name="dname-no-cname",
    description="发布 DNAME 后查询其子名，观察 PowerDNS 是否会遗漏应合成的 CNAME。",
    expected_codes=("DNAME_NO_CNAME",),
    qname="host.alias.example.com.",
    rrtypes="A",
    extra_example_records=("alias.example.com. 300 IN DNAME target.example.net.",),
    fix_message="fixing DNAME response by ensuring synthesized CNAME is included with the DNAME answer.",
)
