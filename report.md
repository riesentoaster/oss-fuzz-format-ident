## Headline numbers

|                           | harnesses | share | median *n* | of which *n*≤4 | distinct corpora |
|---------------------------|----------:|------:|-----------:|---------------:|-----------------:|
| **single**                |       805 |   22% |         38 |            174 |              513 |
| **multi**                 |       152 |    4% |        426 |              0 |               54 |
| **single_unverified**     |       526 |   15% |          3 |            289 |              371 |
| **ambiguous**             |       336 |    9% |            |                |              261 |
| **unknown**               |     1,784 |   50% |            |                |            1,351 |
| total                     |     3,603 |       |            |                |            2,550 |
| formats in confident list |       175 |       |            |                |                  |

Corroboration paths for `single`, by which sources agreed on the same seed: all four 456,
filename+libmagic+siegfried 134, filename+libmagic+magika 77, filename+magika+siegfried 41,
filename+magika 31, filename+siegfried 30, filename+libmagic 20, libmagic+siegfried 8,
magika+siegfried 6, libmagic+magika 2.

Confirmed share of the corpus among singles: median **99%**, with 51 below 25%. That is the
inverse of the previous run, where the low-mass tail was where the errors lived.

Label quality, measured against the one signal the algorithm never reads — the harness name:
**92%** of confident verdicts agree with a format named in the harness or project name,
against **84%** before, and the old number was computed generously (any token overlap).

---

## What the previous report flagged, and where it stands

| # | previous problem | status |
|---|------------------|--------|
| 1 | weak identity tokens (`file`, `object`, `disk`) create false corroboration | **gone** — no label is ever tokenised; `samba/fuzz_ndr_atsvc_TYPE_IN` is now `unknown`, `sleuthkit_fls_ntfs` is `img` from real agreement |
| 2 | alias unions build transitive bridges (`javascript`→`Algol68`→`lua`) | **gone** — `tarantool/lua_dump_test` is `single_unverified` / `lua` |
| 3 | `ESC_COUNT` promotes sparse false positives to labels | **gone** — clickhouse is `sql`, suricata/gonids no longer `text/html`, `systemd/fuzz-dns-packet` demoted, `thrift-rust` and `openssl/asn1` now `ambiguous` |
| 4 | `normalize()` leaks `very short file`, `pcapng capture file -` | **gone** — there is no `normalize()` |
| 5 | opaque non-format labels accepted (`t`, `go`, `c`) | **mostly gone** — `libhtp/fuzz_htp` is `html`, and no harness anywhere is labelled `go` (36 of 42 `ngolo-fuzzing` harnesses are `unknown`) |
| 6 | encoding/container confused with content | **unchanged**, see below |
| 7 | label namespace fragmentation | **gone** — 320 identities, each spanning the namespaces: `['ext:html', 'magika:html', 'mime:text/html', 'sf:Hypertext Markup Language']`. Every example the previous report listed (wasm, BinHex, Cabinet, HWP, XML) is now one identity |
| 8 | `multi` quality mixed | **improved**, see below |
| 9 | missed corroboration (`sol`↔`solidity`) | **fixed** — `solidity/solc_ossfuzz` is `single` / `sol` |

---

## Remaining problems

### 1. Container and encoding formats still win over content

The two cases from last time are unchanged, because both are *true* statements about the
bytes and nothing in the corpus contradicts them:

- **26** dlplibs harnesses are labelled `hqx` (BinHex), as confident `single` verdicts. The
  seeds really are BinHex-encoded; the harness parses what is inside (WordPerfect,
  ClarisWorks, MacDraw).
- `graphicsmagick/coder_ORA_fuzzer` → `application/zip`, now only `single_unverified`.
  OpenRaster *is* a zip.

Deciding otherwise needs a notion of "format X contains format Y", which no observer emits
and which cannot be derived from co-occurrence — a container and its content occupy the
same seeds, so they look exactly like synonyms. This is a genuine limitation, not a bug.

### 2. A thin low-share tail persists, though it is no longer where errors are

51 singles confirm under 25% of their corpus. 17 are one XML corpus shared across 12+ Java
projects (n=814, 5.7% confirmed) where the label is nevertheless right, and 8 are `der`.
`MIN_SHARE` is doing real work here, but 5% is a low bar; the reason not to raise it is that
the affected labels are correct, so raising it would only cost recall.

### 3. `single_unverified` is honest but weak, and should not be treated as a result

Precision on the name proxy is **53%** for this tier, against 92% for `single` — expected,
since by construction only one tool ever spoke. The derived class-membership gate removed the
junk (`bin`, `raw`, `textproto`, `go`), but what is left is dominated by generic-but-real
labels: `txt` 52, `iso` 51, `crt` 48, `tar` 30, `pkt` 28. Median corpus size is 3 seeds.
It is useful as a hint and misleading as a catalogue.

The gate also has one visible leak. `ext:txt`, the tier's largest label, should have been
dropped but qualifies because of a single spurious class, `['ext:txt', 'magika:lisp']` — two
labels that co-occur because some project ships Lisp sources named `.txt`. One bad pair
anywhere in the corpus is enough to admit a generic extension here.

### 4. Class naming is derived, and sometimes derives an unhelpful name

Naming picks the most frequent member that spends ≥50% of its appearances inside its own
class. That correctly avoids naming FBX after `autohotkey`, but it produces some names a
human would not choose:

- `suricata/fuzz_siginit` → `csv`, because `.rule` spends only 10% of its appearances
  aligned with anything (it is a corpus-dominating extension), so it is barred from naming
  its own class while magika's `csv` qualifies at 53%.
- `sleuthkit_fls_ntfs_fuzzer` → `img`, `apache-commons-compress/CompressorBZip2Fuzzer` →
  `application/x-bzip2` rather than `bzip2`.

The identity is right in each case; only the display name is debatable.

### 5. A few residual merges from single linkage

The relation is strict enough that classes are small (2–6 members, 320 of them), but three
merge two things a human would separate:

- `['ext:stl', 'magika:stltext', 'mime:application/x-ebu-stl', 'sf:EBU Subtitling…', 'sf:STL … ASCII']`
  — EBU subtitles and stereolithography genuinely share `.stl`.
- `['ext:py', 'ext:vrt', 'magika:python', …, 'sf:Virtual Format (Raster)']` — GDAL `.vrt`
  bridges in.
- `['ext:test', 'ext:wrl', 'magika:tcl', 'mime:model/vrml', …]` — `.test` files that are
  Tcl scripts bridge Tcl to VRML.

Requiring classes to be internally coherent was measured as a fix and rejected: it flags 43
of 320 classes, and nearly all are correct classes where one tool pair merely overlaps
weakly (`.gz`~*GZIP Format* 0.42, `.mp3`~`audio/mpeg` 0.41).

Worth noting one case that degrades gracefully rather than failing. libmagic calls assembly
sources `application/x-wine-extension-ini`, and the two prefer each other strongly enough
(0.60, at the very top of the ambiguous band) that mutual preference cannot reject it. But
the wrong label simply joins the right class, `['ext:asm', 'magika:asm',
'mime:application/x-wine-extension-ini']`, which specificity then names `asm`. A
systematically wrong tool output is absorbed rather than propagated.

### 6. `multi` is much better but still contains splits that should be merges

Good and clearly right: `apache-poi/POIFuzzer` xls+xlsx, `apache-tika/OOXMLParserFuzzer`
docx+xlsx+pptx, `dng_sdk` and `libvips` tiff+jpg, `libdwarf` elf+PE (33 harnesses, all one
project sharing a corpus).

Still dubious — these are one format under two names, or one format family, that linkage did
not merge:

- `libreoffice/qpwfuzzer` → *Quattro Pro Spreadsheet for Windows* + *…for DOS*, exactly as
  the previous report described. Two siegfried names for one thing, on 8 seeds.
- `pcap` + `pcap Next Generation Packet Capture` (11 harnesses, all `ndpi`) — arguably two
  formats, arguably one.
- `apache-poi/POIVisioFuzzer` → *Microsoft Visio Drawing* + `…visio.drawing.main+xml`.
- `ttf` + `application/vnd.ms-opentype` (6, including `freetype2/ftfuzzer`).

The previous report's worst cases are gone: `bitcoin-core/asmap_direct` and `ots/ots-fuzzer`
are now `ambiguous`, `igraph/read_pajek` is `unknown`, and `upx`'s three ELF flavours are a
single `elf`.

Note also that `multi` concentrates in few projects — 33 `libdwarf`, 21 `libjpeg-turbo`,
19 `libvips`, 11 `ndpi` — because within a project the same mixed corpus is shipped to many
harnesses. 152 verdicts cover only 54 distinct corpora.

### 7. Half the corpus is `unknown`, and that is the real ceiling

1,784 harnesses (1,351 distinct corpora) get no label because no two sources ever agreed on
a single seed. This is a data property: for these corpora every tool reports noise on most
seeds. The `unknown` share went *up* from 36% to 50% versus the previous run, which is the
intended trade — the difference is almost entirely harnesses that previously received a
label from a single channel's unchecked majority.

The lever here is coverage, not cleverness. 456 of 805 confident verdicts have all four
sources agreeing, so adding a fifth independent observer would likely convert a meaningful
slice of `unknown`; no threshold change will.

---

## Bottom line

The failure modes the previous report described were structural, and removing the structure
removed them: there is no tokeniser, no alias table, no normalisation, and no cross-channel
majority comparison left to go wrong. Precision on the independent name check rose from 84%
to 92% while the confident list stayed the same size (805 versus 823), and the residue is
now dominated by *conservatism* — things left `unknown` or `ambiguous` — rather than by
confident errors.

What I would still not present as a catalogue: `single_unverified` (53% on the name proxy),
and the 26 BinHex dlplibs labels, which are true about the bytes and wrong about the
harness. Everything in `single` with a normal share I would now trust.

The two open questions worth a decision are whether container formats should ever lose to
their content (problem 1), and whether `multi` should keep splitting `pcap` from `pcapng`
and `ttf` from OpenType (problem 6). Both are format-modelling questions rather than
algorithm bugs, and answering either means telling the code something about formats that
the corpus cannot tell it.
