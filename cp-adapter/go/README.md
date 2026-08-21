# cp-adapter — Go variant (reference)

An earlier, smaller Go implementation of the same `/exchange` bridge. Kept because it is a
useful second reading of the protocol (and easier to drop into a Go-only deployment), but
**`../adapter.py` is the maintained one** — it has the verified-lane group gating and the
fail-closed behaviour described in `../THREAT_MODEL.md`. This variant does not.
