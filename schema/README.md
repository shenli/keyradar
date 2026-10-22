# Metadata schemas

These JSON Schema 2020-12 files describe the serialized case and report structures. Both use `schema_version: 1`. Generate with `python3 scripts/generate_schemas.py`; CI checks for drift with `--check`.

The schemas enforce structure and primitive types. Runtime `model.Case.Validate` additionally checks allowed enums, references and resource bounds. They are not a replacement for runtime validation or a guarantee that arbitrary user-supplied metadata is safe to share. Only the report builder's `--shareable` projection is intended for agent context.

The private case includes account/key identifiers and source labels. A shareable report omits those and uses report-local credential/location/task aliases. See `integrations/codex/keyradar/references/report.md` for interpretation.
