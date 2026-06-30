⚠️ THIS IS ENTIRELY VIBE CODED ⚠️ </br>
⚠️ USE WITH CAUTION ⚠️ </br>
⚠️ NO GUARANTEES ⚠️


# OSS-Fuzz Harness Format Detector

Detect harness input formats from infra-published build artifacts. **No hand-maintained format list.**

## Usage

```bash
python3 detect_formats.py --output harness_formats.jsonl
python3 detect_formats.py --max-seeds 500 --output harness_formats.jsonl
```

Writes two files:
- `harness_formats.jsonl` — one record per harness
- `format_index.json` — labels grouped to project/harness lists (regenerated from the JSONL at end of run)

---

## Classification rules

Exact rules implemented in code. OSS-Fuzz / ClusterFuzz logic is noted inline where it applies to **filtering** (what gets processed).

### 0. Projects and builds

**Project list** — OSS-Fuzz repo layout: enumerate subdirectories of `oss-fuzz/projects/` that contain a `project.yaml`. A local checkout is required for this list.

**Build download** — follows [`infra/cifuzz/clusterfuzz_deployment.py`](https://github.com/google/oss-fuzz/blob/master/infra/cifuzz/clusterfuzz_deployment.py) `OSSFuzz.get_latest_build_name` / `download_latest_build`:

- Bucket: `clusterfuzz-builds` on `https://storage.googleapis.com/`
- Version file: `{project}-{sanitizer}-latest.version` (default sanitizer: `address`)
- Build zip: `{bucket}/{project}/{build_name}`
- 404 on version file → project skipped

### 1. Which files count as harnesses

A file in an unpacked build zip is a harness if **all** of the following hold:

- It is a regular file (not a directory).
- Its name (without extension) matches `^[a-zA-Z0-9_-]+$`. *(from [`infra/utils.py`](https://github.com/google/oss-fuzz/blob/master/infra/utils.py) `is_fuzz_target_local` / ClusterFuzz `bot/fuzzers/utils.py`)*
- Its extension is empty or `.exe`. *(same source)*
- It is **not** blocklisted:
  - `jazzer_driver*` *(same source)*
  - `afl-*`, `centipede`, `jazzer_*`, `llvm-symbolizer` *(from [`infra/helper.py`](https://github.com/google/oss-fuzz/blob/master/infra/helper.py) `_get_fuzz_targets`)*
- It is **not** a non-harness artifact: `*.zip`, `*.dict`, `*.options`.
- It ends with `_fuzzer`, **or** its binary contents contain `LLVMFuzzerTestOneInput`. *(same source as `is_fuzz_target_local`)*

GCS build zips do not preserve the executable bit, and JVM targets may not be executable for non-root — so unlike `is_fuzz_target_local` / `helper.py:_get_fuzz_targets`, we do not require `os.access` or `st_mode & 0o111`.

### 2. Artifact pairing

Each harness is paired with bundled build outputs using OSS-Fuzz `$OUT` naming conventions ([`docs/getting-started/new_project_guide.md`](https://github.com/google/oss-fuzz/blob/master/docs/getting-started/new_project_guide.md)). `{harness}` is the executable filename as stored in the build (e.g. `yyjson_fuzzer` or `foo_fuzzer.exe` on Windows targets):

| Artifact | Resolution order |
|----------|------------------|
| Seed corpus | `{harness}_seed_corpus.zip`, else `seed_corpus.zip` |
| Dictionary | `{harness}.dict` |

If no seed corpus is paired, seed-based observations are empty for that harness.

### 3. Observations (always collected)

Observations are recorded regardless of the final label.

#### 3a. Seed extensions

From zip entry paths in the paired seed corpus:

- Zip directory entries (paths ending in `/`) are skipped.
- All seed files are counted unless `--max-seeds` is set (first entries in zip order; default `0` = no limit).
- Extension is taken from the entry basename (path after last `/`).
- Compound suffixes are recognized as a single extension: `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.tar.zst`, `.json.gz`, `.xml.gz`.
- Otherwise: extension is `.` + the part after the last `.`, lowercased.
- No dot in basename → extension is `""` (empty string).
- Result: `seed_extensions` map of extension → count, e.g. `{".json": 42, "": 3}`.

#### 3b. Magic bytes and file types

From seed files in the paired corpus (same member list as §3a; subject to `--max-seeds`):

- **Magic**: first 8 bytes of each non-empty seed, hex-encoded. Listed by frequency (top 20).
- **File type**: `file --brief` run on each non-empty seed's bytes (skipped if `file` is not installed). Listed by frequency (top 20).

Empty seed files still count toward `seed_extensions` but are skipped for magic and file-type signals.

#### 3c. Dictionary tokens

If `{harness}.dict` exists:

- All double-quoted strings are extracted using standard **AFL dictionary syntax** (the format OSS-Fuzz projects use for `.dict` files).
- `dict_name` is set to the dict filename without `.dict`.

Dict tokens are **observations only** — they do not affect the label.

#### 3d. Harness name tokens

The executable name is tokenized:

1. Strip trailing `.exe` if present.
2. Split on `_`, `-`, `.`.
3. Split camelCase boundaries (`parseXml` → `parse`, `xml`).
4. Lowercase each token.
5. Drop tokens in the stopword set: `fuzzer`, `fuzz`, `parse`, `parser`, `test`, `target`, `llvm`, `lib`, `run`, `one`, `input`, `data`, `file`, `read`, `decode`.
6. Deduplicate, preserve order.

Name tokens are **observations only** — they affect confidence, not the label directly.

### 4. Label assignment

Labels are chosen by strict priority. First matching rule wins.

#### Rule A — Dominant seed extension

If the most common seed extension accounts for **≥ 50%** of counted seeds:

- **Label** = that extension literally (e.g. `.json`, `.tar.gz`), or `(no extension)` if the extension string is empty.
- Ties for top count are broken alphabetically by extension string.

#### Rule B — File type

Else, if any `file --brief` results were collected:

- **Label** = the most frequent `file --brief` string verbatim (e.g. `JSON text data`, `ASCII text`).

#### Rule C — Magic prefix

Else, if any magic prefixes were collected:

- **Label** = `magic:` + the most frequent 8-byte hex prefix (e.g. `magic:1f8b0800`).

#### Rule D — Unknown

Else:

- **Label** = `unknown`
- **Confidence** = `null`

### 5. Confidence

Confidence is only set when a non-unknown label is assigned.

When **Rule A** applies (dominant extension):

| Condition | Confidence |
|-----------|------------|
| Top extension ≥ 90% of counted seeds | `high` |
| Top extension ≥ 50% and `< 90%` | `medium` |
| Extension stem (without dot) appears as a substring in the top `file --brief` result | upgraded to `high` (checked first) |
| Extension stem is an exact match among harness `name_tokens` | upgraded to `high` |

Upgrades are applied in order: file-type agreement is checked before name-token agreement.

When **Rule B** applies (file type only):

- **Confidence** = `medium`

When **Rule C** applies (magic only):

- **Confidence** = `low`

### 6. Evidence and signal_labels

Each record also includes:

- **`evidence`**: human-readable strings describing which observations triggered the label/confidence (extension percentage, file type, magic prefix, name-token match).
- **`signal_labels`**: the raw values used per signal type:
  - `extension` — dominant extension label (Rule A candidate)
  - `content` — top `file --brief` string
  - `magic` — top hex prefix

These are informational. The `label` field follows the priority rules in §4.

### 7. format_index.json

After the run, all `harness_formats.jsonl` records are grouped by their `label` field:

```json
{
  ".json": [
    {"project": "yyjson", "harness": "yyjson_fuzzer", "confidence": "high"}
  ]
}
```

- Entries within each format are sorted by `(project, harness)`.
- `confidence` is included when non-null.
- Formats are sorted alphabetically by label.

---

## Output schema (harness_formats.jsonl)

```json
{
  "project": "yyjson",
  "harness": "yyjson_fuzzer",
  "build": "yyjson-address-202606300604.zip",
  "observations": {
    "seed_extensions": {".json": 500},
    "seed_types": ["JSON text data"],
    "magic_prefixes": ["7b0a2022"],
    "dict_tokens": ["{", "}"],
    "name_tokens": ["yyjson"],
    "dict_name": "yyjson_fuzzer"
  },
  "label": ".json",
  "confidence": "high",
  "evidence": ["100% .json seed extensions"],
  "signal_labels": {"extension": ".json", "content": "JSON text data"}
}
```
