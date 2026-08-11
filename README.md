# SOC Alert-Enrichment Agent (POC)

Takes a raw SIEM alert (Splunk notable / Elastic ECS / CEF / generic JSON / free text) and
produces an analyst-ready enrichment as JSON: extracted IOCs, threat-intel verdicts,
related-alert history, MITRE ATT&CK mapping, a transparent risk score, and an
**escalate / investigate / close** recommendation with a concise briefing.

Built as a fixed LangGraph pipeline; LLM = **Qwen3.7 Max** via Alibaba Cloud Model Studio
(DashScope, OpenAI-compatible endpoint). All external data (threat intel, alert history) is
mocked in the POC behind provider interfaces, so real feeds drop in later as config changes.

Specs live in [`specs/`](specs/) — start with [`Architecture.md`](specs/Architecture.md),
then the numbered implementation specs (`project-setup-01-spec.md`, …).

## Quickstart

```bash
make install                 # editable install into .venv
cp .env.example .env         # then add your DASHSCOPE_API_KEY
make check                   # config + key + live model round-trip (~50 tokens)
make test                    # unit tests (never calls the API)
```

## Commands

```bash
soc-agent check              # setup diagnostics (implemented)
soc-agent normalize ALERT    # canonical alert JSON         (spec 03)
soc-agent extract ALERT      # extracted entities + IOCs    (spec 04)
soc-agent context ALERT      # threat intel + alert history (spec 05)
soc-agent seed               # build data/history.db        (spec 05)
soc-agent enrich ALERT       # single-alert enrichment      (spec 08)
soc-agent enrich-dir DIR     # batch enrichment             (spec 08)
soc-agent eval               # labeled eval set + metrics   (spec 09)
soc-agent schema             # export output JSON Schema    (spec 02)
```
