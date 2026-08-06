# Review verdicts — codec v5, D2a, D2b (combined round)

Overall gate: **RETURN / do not advance.** All mandatory test, Clippy and
formatting gates passed; the blockers survived those gates.

## Codec v5 — `d8795fa`: dual RETURN

- Fable: `u64::MAX` counter wrap can replace retained OTK ID 0
  (`wrapping_add` after a `u64::MAX` `next_key_id` selects 0).
- Sol: full plaintext copied into a non-zeroizing `Vec`.
- Sol: send/receive/manage mailbox capabilities may collapse to one key.

## D2a — `16adc90`: RETURN (Fable PASS, Sol RETURN)

- Sol: `record_send_result` does not validate the returned request's
  `message_id`; it substitutes the stored ID
  (`src/persistent/mod.rs:872` at the reviewed head).

## D2b — `cf891ea`: dual RETURN

- Both reviewers: incomplete ACK-result binding — `message_id` and signature
  are not validated before removing the ACK intent
  (`src/persistent/mod.rs:1101` at the reviewed head).
- Sol additionally: required public façade types are not exported
  (`src/lib.rs:29`); expired pending ACK intents are never swept, eventually
  exhausting bounded ACK slots.

Process note: the initial Sol D2b output was classifier-blocked; a fresh
isolated Sol replacement completed the independent ruling.
