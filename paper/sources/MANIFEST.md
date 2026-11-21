# Source manifest — URL and SHA-256 of every version cited

This manifest lists, for every external source cited in the paper, the
exact version read, the canonical IETF / arXiv / repository URL from
which it was retrieved, and the SHA-256 of the bytes that were read.
Every claim in the paper that pins a section number to a draft is
verified against the file at the hash below. The companion draft
`draft-hood-agtp-standard-methods-01` was retrieved through the IETF
archive (Cloudflare-protected); no hash is recorded for it
(see the table row). Where a draft is an IETF Internet-Draft, the
canonical URL form is `https://www.ietf.org/archive/id/<draft>.txt`.

| Source | Version cited | URL | SHA-256 (of the bytes read) |
| --- | --- | --- | --- |
| `I-D.hood-agtp` (AGTP) | draft-hood-independent-agtp-09, 2026-06-28 | https://www.ietf.org/archive/id/draft-hood-independent-agtp-09.txt | `3c033c5920b2d70c19531d9608397ff52ce907f62f013dfa4d6c972bff447c41` |
| `I-D.hood-agtp-standard-methods` (AGTP Standard Extended Method Vocabulary) | draft-hood-agtp-standard-methods-01, 2026-04-16 (expired 2026-10-18) | https://www.ietf.org/archive/id/draft-hood-agtp-standard-methods-01.txt | (Cloudflare-protected; not retrievable by automated tools. The paper cites §8.7 RESUME per the change plan and notes the expiry in the bibliography. A future revision will record the hash directly.) |
| `I-D.hood-agtp-session` (AGTP Session Protocol) | draft-hood-agtp-session-00, 2026-04-30 | https://www.ietf.org/archive/id/draft-hood-agtp-session-00.txt | `29bcd0d5983ea5c4e786b5a462f1af059a8b9fe3c7e8852a528be13c069c002b` |
| `I-D.hood-agtp-bindings` (AGTP Transport Bindings) | draft-hood-agtp-bindings-00, 2026-06-28 | https://www.ietf.org/archive/id/draft-hood-agtp-bindings-00.txt | `a5564aa64ec6da89ae22b165550b532045d20609c679554154d0657895106877` |
| `I-D.sato-soos-gar` (GAR) | draft-sato-soos-gar-08, 2026-09-07 | https://www.ietf.org/archive/id/draft-sato-soos-gar-08.txt | `ecdcc56048358b32b690e5f025767bdb37ab62698d451655ef685e7e67b002ef` |
| `I-D.sato-soos-hem` (HEM) | draft-sato-soos-hem-07, 2026-09-05 | https://www.ietf.org/archive/id/draft-sato-soos-hem-07.txt | `65bddc8b93cd0c27e282dabd03de32e4152894022fc7c023c821d2eafc3c5c97` |
| `I-D.nandakumar-agentproto-moq-pace` (PACE) | draft-nandakumar-agentproto-moq-pace-00, 2026-06-28 | https://www.ietf.org/archive/id/draft-nandakumar-agentproto-moq-pace-00.txt | `356af3e266f246bf8bd712f8e98015b93bf1fbfeae715918e28dc1608c98da52` |
| `I-D.sharif-agent-audit-trail` (Agent Audit Trail) | draft-sharif-agent-audit-trail-01, 2026-08-19 | https://www.ietf.org/archive/id/draft-sharif-agent-audit-trail-01.txt | `34ccfa1c5b19d6e1a47478347337a8f9b6feab5e330037938ed32ca9d90c9fad` |
| `I-D.mih-sato-agent-accountability-composition` | draft-mih-sato-agent-accountability-composition-01 | https://www.ietf.org/archive/id/draft-mih-sato-agent-accountability-composition-01.txt | `44da33757a2cb6534885a5d1791f3cd8b1f1cfbc2e51d3a9b12c33a72aedfdc9` |
| `I-D.sokolov-rats-aep-composition` | draft-sokolov-rats-aep-composition-06 | https://www.ietf.org/archive/id/draft-sokolov-rats-aep-composition-06.txt | `311123dea40b598478d1fe8e898db204044f2eb8332a0d6c292795f914f44d4c` |
| `zheng2026formal` (AgentThread) | arXiv:2606.28690v1, 2026-06-27 | http://arxiv.org/abs/2606.28690v1 | `8db4a739a4edaeccb81a81cbf759260187e35fbf9e823150199d7a1e5dfb4d8d` (PDF) |
| `herdr-product` (Herdr) | Herdr repository, commit `bc8c289` (2026-10-28); documentation version 0.9.5 | https://github.com/herdrdev/herdr ; https://herdr.dev/docs/session-state/ | `9b3943664e3c4cf928c1e317f1de632d9a051e59c4b8b6b0e93f1decc43dbb3d` (README at the cited commit); `ad98fac05b1f4eb513bbb25808d1d714168b3c7fcfa8a4ba304fdb376e7e8fef` (session-state.html, version 0.9.5); `1eb85fc97224598dad1852b5d6483bbcf0aa8608790dcc657a5a2a761ae9c8c6` (LICENSE) |
| `termenbox` (Termenbox) | Termenbox product site, state as reported by the author on 2026-10-28 | https://termenbox.dev/ | (Closed source; no bytes are deposited and none can be checked by a reader. The paper treats claims about it as reported by the author.) |

## Notes on verification

* Every section pin in the paper (AGTP-09 §8.2.12, AGTP-SESSION §10.5,
  AGTP-BINDINGS §4.6, GAR §3 and §6.1, HEM §4, §5, §12.8, §13.1, §14.1
  and §14.2, PACE §4.5, §5.1.2, §9.1.2 and the message-type registry,
  Agent Audit Trail §4, §6, §7, §8.1–§8.3, and the Herdr 0.9.5
  `session.json` documentation) was opened at the file whose hash is
  listed above and checked against the wording in the paper.
* The companion draft `draft-hood-agtp-standard-methods-01` lists a
  RESUME method in its §8.7. Its bytes were not retrievable by
  automated tools because the IETF archive sits behind a Cloudflare
  challenge; the paper cites it on the strength of the change plan
  that prompted this revision and flags the limitation in the
  bibliography note. A future revision will record the hash directly
  when an accessible copy is obtained.
