# PowerDNS 剩余 DNSSEC 错误码修复方案

本文档记录 PowerDNS Authoritative (`pdns-server + pdns-backend-bind + PRESIGNED`) 口径下尚未命中目标 DNSViz code 的 32 个 DNSSEC 相关错误码的修复方案。

这里的“未命中”只表示当前 PowerDNS demo 不能稳定触发对应 DNSViz code；不等于该错误没有修复方法。很多错误在真实系统中仍然可以修，只是需要更高权限、更底层响应控制，或需要在 BIND9/NSD/Knot/custom responder 等其他权威实现中诊断。

当前基线：

```text
DNSSEC 相关 DNSViz 错误码：77
PowerDNS 已命中：45
PowerDNS 未命中：32
PowerDNS 可运行 demo 场景：67
场景级 target-ok：48
场景级 target-miss：19
```

最新未试项补充实验结论：

| DNSViz 响应码 | 候选构造 | PowerDNS/DNSViz 实测结果 | 结论 |
|---|---|---|---|
| `REFERRAL_FOR_DS_QUERY` | 父区无 DS 时查询 `example.com. DS` | `target-miss`，before/after 均 `<none>` | PowerDNS 正确返回 authoritative NODATA，没有错误 referral。 |
| `INVALID_NSEC3_HASH` | 将 NSEC3 next hash 改成非法长度并重新签名 | `target-miss`，before 为 `SIGNATURE_INVALID` | DNSViz/PowerDNS 路径先进入签名无效，未到非法 hash 语义分支。 |
| `INVALID_NSEC3_OWNER_NAME` | 将 NSEC3 owner 改成非法 Base32hex label 并重新签名 | `target-miss`，before 为 `MISSING_RRSIG` | PowerDNS/DNSViz 组合未接受该畸形 owner 作为有效 proof 输入。 |
| `NEXT_CLOSEST_ENCLOSER_NOT_COVERED` | 篡改覆盖 next closest encloser 的 NSEC3 next hash | `target-miss`，before 为 `SIGNATURE_INVALID` | 精确 proof 矛盾被签名验证抢占。 |
| `OPT_OUT_FLAG_NOT_SET` | 生成 unsigned delegation 的 NSEC3 opt-out proof 后清除 opt-out flag | `target-miss`，before 为 `MISSING_RRSIG, NO_ADDRESS_FOR_NS_NAME, SERVER_NOT_AUTHORITATIVE`；若 PowerDNS metadata 设置 opt-out，wire flag 会被规整回 `1` | PowerDNS bind backend 会按 metadata 规整 NSEC3 opt-out wire 行为；不适合稳定触发该码。 |
| `DNSKEY_BAD_LENGTH_GOST` | 将 ZSK DNSKEY algorithm 改为 GOST(12)，并替换为错误长度公钥 | `target-ok`，before 为 `DNSKEY_BAD_LENGTH_GOST, MISSING_RRSIG_FOR_ALG_DNSKEY, NO_SEP, SIGNATURE_INVALID`，after 为 `<none>` | 可保留为 PowerDNS 原生 target-ok demo；修复逻辑是移除 GOST/非法 DNSKEY，换用有效推荐算法并重签。 |
| `RRSIG_BAD_LENGTH_GOST` | 将 `www A` 的 RRSIG algorithm 改为 GOST(12)，并分别替换为 1 字节和 63 字节错误长度签名 | `target-miss`，before 为 `INVALID_RCODE`；authoritative `dig` 直接返回 `SERVFAIL` | PowerDNS 与其他 RRSIG bad-length 场景一致，wire 层退化为非法响应。 |
| `DNAME_NO_CNAME` | 发布 `alias.example.com. DNAME target.example.net.` 后查询 `host.alias.example.com. A` | `target-miss`，before/after 均 `<none>`；authoritative 响应为 `NXDOMAIN` + `alias.example.com. NSEC ... DNAME ...`，不返回 DNAME RR 本身 | DNSViz 没有 DNAME 响应对象可分析，无法进入 `DNAME_NO_CNAME` 分支。 |
| `RRSET_TTL_MISMATCH` | 将 `www.example.com. A` TTL 降到 200，避免超过 RRSIG original TTL | `target-miss`，before/after 均 `<none>`；wire 响应中 PowerDNS 将 RRSIG TTL 也规整为 200 | PowerDNS 会把 RRset/RRSIG TTL 规整一致；高 TTL 变体则归并为 `ORIGINAL_TTL_EXCEEDED_*`。 |
| `NO_CLOSEST_ENCLOSER` | 改为 empty salt / iteration 0 后删除 closest-encloser 对应 NSEC3 RRset | `target-miss`，before 为 `MISSING_RRSIG`；wire 响应中 PowerDNS 合成被删除的 NSEC3 RR，但没有对应 RRSIG | 已排除 NSEC3 policy 干扰；PowerDNS 自动合成 proof 导致缺签名错误抢占。 |
| `WILDCARD_COVERED` / `WILDCARD_NOT_COVERED` | 改为 empty salt / iteration 0 后篡改 wildcard 相关 NSEC3 next hash | `target-miss`，before 为 `SIGNATURE_INVALID`；wire 响应中 PowerDNS 将 NSEC3 next hash 规整回 canonical 链 | 已排除 NSEC3 policy 干扰；PowerDNS 改写派生 proof 导致签名错误抢占。 |
| `SNAME_COVERED` | 双权威尝试：主权威返回 `empty` 存在但无 A，副权威返回 `empty` 不存在 | `target-miss`，before/after 均 `<none>` | DNSViz 没有把这种多权威 NODATA/NXDOMAIN 差异归并为 `SNAME_COVERED`。 |

这 32 个不是“没有修复方案”。按跨后端状态拆分：

```text
PowerDNS 未命中但 BIND9 已有 target-ok demo：12
PowerDNS 与 BIND9 均未稳定命中，需要 custom responder/父区行为/策略触发/算法栈支持：20
```

DFixer 对这些 code 的核心修复逻辑可以规约为几类：

| DFixer/扩展逻辑 | 覆盖 code | 修复动作 |
|---|---|---|
| NSEC/NSEC3 proof/bitmap 重建 | `LAST_NSEC_NEXT_NOT_ZONE`, `NO_CLOSEST_ENCLOSER`, `NO_NSEC3_MATCHING_SNAME`, `NO_NSEC_MATCHING_SNAME`, `OPT_OUT_FLAG_NOT_SET`, `SNAME_*`, `STYPE_IN_BITMAP`, `UNSUPPORTED_NSEC3_ALGORITHM`, `WILDCARD_*`, `INVALID_NSEC3_*`, `NEXT_CLOSEST_ENCLOSER_NOT_COVERED` | 丢弃现有 denial-of-existence 派生数据，重新生成 NSEC/NSEC3；NSEC3 使用 algorithm 1、iteration 0、empty salt；重签 zone。 |
| 父区委派 bitmap 修复 | `REFERRAL_WITHOUT_NS`, `REFERRAL_WITH_DS`, `REFERRAL_WITH_SOA` | 在父区修正委派点 NSEC/NSEC3 bitmap：必须包含 `NS`，不应错误包含 `SOA`，`DS` bit 与实际 DS 响应一致；父区重签。 |
| DNSKEY 清理/替换 | `DNSKEY_ZERO_LENGTH` | 删除非法/零长度/revoked 错误 key，生成有效 KSK/ZSK，必要时同步父区 DS，重签。 |
| TTL/签名重签 | `RRSET_TTL_MISMATCH` | 统一 RRset TTL、RRSIG TTL、original TTL；必要时降低 TTL 或延长签名有效期，重签。 |
| RRSIG bad length | `RRSIG_BAD_LENGTH_*` | 丢弃错误长度签名，用正确算法和私钥重新签名；废弃算法迁移到推荐算法并同步 DS。 |
| 服务端响应行为 | `DNAME_*`, `REFERRAL_FOR_DS_QUERY` | 修权威服务器/代理/父区响应逻辑；这不是 zone 签名器能单独修的派生数据问题。 |
| DNSViz inactive policy | `DIGEST_ALGORITHM_NOT_RECOMMENDED`, `DIGEST_ALGORITHM_VALIDATION_PROHIBITED` | 当前 DNSViz 策略集合为空；策略启用后删除弱/禁用 digest DS，发布 SHA-256/SHA-384 DS 并重签父区。 |

其中，BIND9 已能复现并闭环修复的 12 个 PowerDNS 剩余码如下：

| DNSViz 响应码 | BIND9 场景 | DFixer/执行器修复动作 |
|---|---|---|
| `LAST_NSEC_NEXT_NOT_ZONE` | `last-nsec-next-not-zone` | 重建 NSEC 链，使最后一条 NSEC 指回 zone apex，并重签。 |
| `NO_CLOSEST_ENCLOSER` | `no-closest-encloser` | 重建完整 NSEC3 closest-encloser proof 并重签。 |
| `NO_NSEC3_MATCHING_SNAME` | `no-nsec3-matching-sname` | 重建匹配 SNAME 的 NSEC3 proof 并重签。 |
| `NO_NSEC_MATCHING_SNAME` | `no-nsec-matching-sname` | 重建匹配 SNAME 的 NSEC proof 并重签。 |
| `REFERRAL_WITHOUT_NS` | `referral-without-ns` | 父区委派 proof 恢复 `NS` bit 并重签父区。 |
| `REFERRAL_WITH_DS` | `referral-with-ds` | 父区委派 proof 修正 `DS` bit/DS 响应语义并重签父区。 |
| `REFERRAL_WITH_SOA` | `referral-with-soa` | 父区委派 proof 移除错误 `SOA` bit 并重签父区。 |
| `SNAME_NOT_COVERED` | `sname-not-covered` | 重建覆盖 SNAME 的 NSEC/NSEC3 proof 并重签。 |
| `STYPE_IN_BITMAP` | `stype-in-bitmap` | 重建 NODATA proof bitmap，移除错误 stype，并重签。 |
| `WILDCARD_COVERED` | `wildcard-covered` | 重建 wildcard denial proof，避免覆盖实际存在的 wildcard，并重签。 |
| `WILDCARD_NOT_COVERED` | `wildcard-not-covered` | 补齐覆盖 wildcard 名称的 proof，并重签。 |
| `RRSET_TTL_MISMATCH` | `rrset-ttl-mismatch` | 统一 RRset/RRSIG TTL 并重签。 |

## 执行器分层

| 执行器 | 适用对象 | 典型动作 |
|---|---|---|
| `child-zone repair` | 子区 zone 数据、DNSKEY、RRSIG、NSEC/NSEC3、CDS/CDNSKEY | 修改 zone/backend、重签、reload/rectify |
| `multi-auth sync` | 多个权威服务器返回不一致 | 统一 zone serial、同步 DNSKEY/RRSIG/RRset、逐 NS 验证 |
| `parent-side repair` | 父区 DS、委派侧响应 | 调父区/注册商/API 更新 DS 或修正委派 |
| `server-behavior repair` | DNAME 合成、DS 查询 referral、协议响应异常 | 修改/升级权威服务器配置或实现 |
| `custom responder required` | 普通权威软件会规整或拒绝的畸形响应 | 用 wire-level/custom responder 复现；生产修复通常是消除畸形响应 |
| `inactive policy` | DNSViz 当前策略集合为空 | 当前不可触发；保留未来策略启用后的修复规则 |

## 剩余 32 个错误码修复矩阵

| 编号 | DNSViz 响应码 | PowerDNS 当前状态 | 修复能力 | 所需权限 | 修复方案 |
|---:|---|---|---|---|---|
| 1 | `DNAME_NO_CNAME` | 已尝试；PowerDNS 对 DNAME 子名查询返回 `NXDOMAIN`/NSEC，不返回可供 DNSViz 判定的 DNAME RR | 不属于 zone 签名修复，属于权威响应逻辑修复 | 权威服务器配置/实现 | 确认 DNAME owner 与目标；修复或升级权威服务器，使 DNAME 查询响应包含规范合成的 CNAME；若是代理/网关丢弃 CNAME，修复中间层响应拼装逻辑。 |
| 2 | `DNAME_TARGET_MISMATCH` | 普通权威会正确合成目标，需 custom responder 才能复现 | 不属于 zone 签名修复，属于权威响应逻辑修复 | 权威服务器配置/实现 | 按 RFC 6672 重新计算 DNAME 合成目标；修正权威软件或中间层中错误的 owner/target 拼接；必要时删除错误 DNAME 或改成显式 CNAME。 |
| 3 | `DNAME_TTL_MISMATCH` | 普通权威会统一 DNAME/CNAME TTL | 不属于 zone 签名修复，属于响应 TTL 生成修复 | 权威服务器配置/实现 | 让合成 CNAME TTL 等于 DNAME TTL；排查 DNS proxy、response rewrite、cache layer 是否改写其中一方 TTL。 |
| 4 | `DNAME_TTL_ZERO` | 普通权威不会稳定产生 TTL 0 的合成 CNAME | 不属于 zone 签名修复，属于响应 TTL 生成修复 | 权威服务器配置/实现 | 禁止合成 CNAME 使用 0 TTL；将 DNAME TTL 设置为正常值，并确认中间层不会把合成记录 TTL 改为 0。 |
| 5 | `DNSKEY_ZERO_LENGTH` | 已尝试；PowerDNS 退化为 `INVALID_RCODE`/`SERVER_INVALID_RESPONSE_UDP` | 可修 | 子区 DNSKEY/签名权限 | 立即移除零长度 DNSKEY；重新生成有效 KSK/ZSK；用新 key 重签所有 RRset；若父区 DS 指向受影响 KSK，同步更新父区 DS。 |
| 6 | `DIGEST_ALGORITHM_NOT_RECOMMENDED` | DNSViz 0.11.1 策略集合为空，当前不可触发 | 可修，策略启用后执行 | 父区 DS 权限 | 移除不推荐 digest 的 DS，发布 SHA-256 或 SHA-384 DS；父区重签；验证 DS digest 与子区 KSK 匹配。 |
| 7 | `DIGEST_ALGORITHM_VALIDATION_PROHIBITED` | DNSViz 0.11.1 策略集合为空，当前不可触发 | 可修，策略启用后执行 | 父区 DS 权限 | 移除 validation-prohibited digest 的 DS，发布推荐 digest DS；父区重签；等待缓存过期后验证链路。 |
| 8 | `REFERRAL_FOR_DS_QUERY` | 已尝试；PowerDNS 正确返回 authoritative NODATA，未产生错误 referral | 可修，但属于父区响应行为 | 父区权威配置/API | 修正父区对 child `DS` 查询的权威处理：存在 DS 时返回 DS；无 DS 时返回 authoritative NODATA，而不是 referral；检查 delegation 配置和 zone cut 判断。 |
| 9 | `INVALID_NSEC3_HASH` | 已尝试；PowerDNS/DNSViz 退化为 `SIGNATURE_INVALID` | 可修；复现需 wire-level/custom responder | 子区 zone/backend | 丢弃非法 NSEC3 链，使用合法 hash algorithm 1 重新生成 NSEC3，或改用 NSEC；重签 zone。 |
| 10 | `INVALID_NSEC3_OWNER_NAME` | 已尝试；PowerDNS/DNSViz 退化为 `MISSING_RRSIG` | 可修；复现需 wire-level/custom responder | 子区 zone/backend | 删除非法 Base32hex NSEC3 owner；重新生成 NSEC3 链；重签 zone；验证所有 NSEC3 owner 均为合法 hash。 |
| 11 | `LAST_NSEC_NEXT_NOT_ZONE` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 子区 zone/backend | 重新生成 NSEC 链，确保最后一条 NSEC 的 next domain 回到 zone apex；重签所有 NSEC RRset。 |
| 12 | `NEXT_CLOSEST_ENCLOSER_NOT_COVERED` | 已尝试；PowerDNS/DNSViz 退化为 `SIGNATURE_INVALID` | 可修；复现需 custom responder | 子区 zone/backend | 重新生成 NSEC3 链，确保 NXDOMAIN proof 同时包含 closest encloser、next closest encloser 覆盖和 wildcard proof；重签 zone。 |
| 13 | `NO_CLOSEST_ENCLOSER` | 已尝试；empty salt/iteration 0 后仍退化为 `MISSING_RRSIG`，PowerDNS 会合成被删除的 NSEC3 RR | 可修 | 子区 zone/backend | 重新生成完整 NSEC3 proof，补齐 closest encloser 对应 NSEC3 RRset；重签 zone。 |
| 14 | `NO_NSEC3_MATCHING_SNAME` | 已尝试；PowerDNS 退化为 `MISSING_RRSIG` | 可修 | 子区 zone/backend | 重新生成 NSEC3 链，确保 NODATA/NXDOMAIN 响应包含匹配 SNAME 的 NSEC3 RRset；重签 zone。 |
| 15 | `NO_NSEC_MATCHING_SNAME` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 子区 zone/backend | 重新生成 NSEC 链，确保 SNAME 对应 NSEC proof 存在且签名有效；重签 zone。 |
| 16 | `OPT_OUT_FLAG_NOT_SET` | 已尝试；PowerDNS metadata 会规整 opt-out flag，关闭 metadata 又退化为 `MISSING_RRSIG` | 可修；复现需 custom responder 或精确 NSEC3 工具 | 子区/父区委派数据权限 | 若确实使用 NSEC3 opt-out，重新生成带 opt-out flag 的覆盖记录；若不需要 opt-out，关闭 opt-out 并完整签名委派区域。 |
| 17 | `REFERRAL_WITHOUT_NS` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 父区/委派侧 zone 权限 | 修正委派点 NSEC/NSEC3 bitmap，确保 referral proof 包含 `NS` bit；同时确认委派 NS RRset 存在并签名有效。 |
| 18 | `REFERRAL_WITH_DS` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 父区/委派侧 zone 权限 | 修正委派 proof 的 bitmap；若 DS 存在，应返回正确 DS；若无 DS，不应在 denial proof bitmap 中错误包含 DS bit；重签父区。 |
| 19 | `REFERRAL_WITH_SOA` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 父区/委派侧 zone 权限 | 修正委派点 bitmap，委派 proof 不应错误包含 `SOA` bit；重签父区并验证 DS/NS 查询行为。 |
| 20 | `SNAME_COVERED` | 已尝试；双权威 NODATA/NXDOMAIN 差异 before/after 均 `<none>`，仍需返回精确矛盾 proof | 可修；复现需 custom responder | 子区 zone/backend | 重新生成 NSEC/NSEC3 denial proof，确保实际存在的 SNAME 不会被 proof 覆盖为不存在；重签 zone。 |
| 21 | `SNAME_NOT_COVERED` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 子区 zone/backend | 重新生成 NSEC/NSEC3 链，使 NXDOMAIN/NODATA proof 覆盖 SNAME；重签 zone。 |
| 22 | `STYPE_IN_BITMAP` | 已尝试；PowerDNS 退化为 `SIGNATURE_INVALID` | 可修 | 子区 zone/backend | 重新生成 NSEC/NSEC3 bitmap，NODATA proof 不应包含被查询的 stype；重签 denial proof。 |
| 23 | `UNSUPPORTED_NSEC3_ALGORITHM` | 已尝试；PowerDNS 退化为 `MISSING_RRSIG` | 可修 | 子区 zone/backend | 使用 NSEC3 hash algorithm 1 重新生成链，或改用 NSEC；重签 zone。 |
| 24 | `WILDCARD_COVERED` | 已尝试；empty salt/iteration 0 后仍退化为 `SIGNATURE_INVALID`，PowerDNS 会规整 NSEC3 next hash | 可修 | 子区 zone/backend | 重新生成 wildcard 相关 denial proof，确保存在的 wildcard 不被 NSEC/NSEC3 覆盖为不存在；重签 zone。 |
| 25 | `WILDCARD_EXPANSION_INVALID` | 未注册；需要正向 wildcard 答案与 proof 精确矛盾 | 可修；复现需 custom responder | 子区 zone/backend | 检查 wildcard RRset、closest encloser 与 next closest encloser proof；重新生成 NSEC/NSEC3 链，保证 wildcard 展开和 denial proof 一致。 |
| 26 | `WILDCARD_NOT_COVERED` | 已尝试；empty salt/iteration 0 后仍退化为 `SIGNATURE_INVALID`，PowerDNS 会规整 NSEC3 next hash | 可修 | 子区 zone/backend | 重新生成 NSEC/NSEC3 proof，补齐覆盖 wildcard 名称的 proof；重签 zone。 |
| 27 | `RRSET_TTL_MISMATCH` | 已尝试；低 TTL 变体被 PowerDNS 规整为一致 TTL，高 TTL 变体变成 `ORIGINAL_TTL_EXCEEDED_*`，未命中本码 | 可修 | 子区 zone/backend | 统一 RRset TTL 与覆盖它的 RRSIG TTL；推荐直接重签整区，让签名器重新写入一致 TTL。 |
| 28 | `RRSIG_BAD_LENGTH_ECDSA256` | 已尝试；PowerDNS 退化为 `INVALID_RCODE` | 可修；复现需 wire-level/custom responder | 子区签名权限 | 丢弃错误长度 RRSIG，使用正确 ECDSA P-256 key 重新签名对应 RRset。 |
| 29 | `RRSIG_BAD_LENGTH_ECDSA384` | 已尝试；PowerDNS 退化为 `INVALID_RCODE` | 可修；复现需 wire-level/custom responder | 子区签名权限 | 丢弃错误长度 RRSIG，使用正确 ECDSA P-384 key 重新签名对应 RRset。 |
| 30 | `RRSIG_BAD_LENGTH_ED25519` | 已尝试；PowerDNS 退化为 `INVALID_RCODE` | 可修；复现需 wire-level/custom responder | 子区签名权限 | 丢弃错误长度 RRSIG，使用正确 Ed25519 key 重新签名对应 RRset。 |
| 31 | `RRSIG_BAD_LENGTH_ED448` | 已尝试；PowerDNS 退化为 `INVALID_RCODE` | 可修；复现需 wire-level/custom responder | 子区签名权限 | 丢弃错误长度 RRSIG，使用正确 Ed448 key 重新签名对应 RRset。 |
| 32 | `RRSIG_BAD_LENGTH_GOST` | 已尝试；PowerDNS 退化为 `INVALID_RCODE` | 可修；不建议继续使用 GOST | 子区签名权限 | 移除 GOST 签名和对应 DNSKEY，迁移到推荐算法并重签；父区 DS 同步更新。 |

## 对真实修复器的落地规则

1. DNSViz 如果精确报出以上任一 code，修复器应优先执行“修复方案”列，而不是依赖 PowerDNS demo 是否能命中。
2. PowerDNS bind backend 下的 NSEC/NSEC3 和 bad-length 类错误常退化为 `MISSING_RRSIG`、`SIGNATURE_INVALID` 或 `INVALID_RCODE`。真实修复时应把这些泛化错误映射为“重建 DNSSEC 派生数据并重签”，不要尝试手工保留畸形记录。
3. 涉及父区 DS、委派和多权威一致性的错误，必须在 repair plan 中显式标注权限需求；没有父区/注册商/API 或全部权威发布权限时，只输出人工修复步骤。
4. `DNAME_*`、`REFERRAL_FOR_DS_QUERY`、部分矛盾 proof 和 wire-level bad-length 类错误，需要 custom responder 才能稳定复现实验；生产修复目标是消除错误响应，而不是复现错误响应。
5. `DIGEST_ALGORITHM_NOT_RECOMMENDED` 和 `DIGEST_ALGORITHM_VALIDATION_PROHIBITED` 当前属于 DNSViz inactive policy。保留修复规则，但不纳入当前自动验证通过率。
