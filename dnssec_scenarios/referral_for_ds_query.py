from .common import Scenario


scenario = Scenario(
    name="referral-for-ds-query",
    description="父区无 DS 时查询 child DS，尝试观察 PowerDNS 是否会错误返回 referral。",
    expected_codes=("REFERRAL_FOR_DS_QUERY",),
    qname="example.com.",
    rrtypes="DS",
    include_example_ds=False,
    fix_message="fixing referral for DS query by making the parent answer DS queries authoritatively with DS or NODATA.",
)
