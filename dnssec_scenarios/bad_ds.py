from .common import Scenario


scenario = Scenario(
    name="bad-ds",
    description="父区 com. 发布 example.com. 的错误 DS digest。",
    expected_codes=("DIGEST_INVALID", "NO_SEP"),
    corrupt_child_ds=True,
    fix_message="fixing bad DS by regenerating correct example.com DS in com. and resigning com.",
)

