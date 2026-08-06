# Identifying the input format of a fuzz harness from its seed corpus

## The problem

Every OSS-Fuzz harness ships a seed corpus: a directory of example inputs. We want to know
what format each harness consumes, so that harnesses can be grouped by format and a
single-format list can be handed to downstream tooling. Harnesses that genuinely accept
several unrelated formats should be recognised as such and set aside rather than forced
into a label.

Three properties of the data make this harder than running `file` over the corpus and
taking the majority answer.

**Corpora are noisy.** Many seeds are minimised crash reproducers, truncated fragments, or
random bytes accumulated by the fuzzer. For a large fraction of seeds, every identification
tool honestly reports "unknown binary data". Worse, the tools do not always fail silently:
libmagic will confidently call a firmware blob an *OpenPGP Public Key*, and a
machine-learning classifier will call a plain-text signature database *PowerShell*.

**The format space is enormous and open-ended.** OSS-Fuzz spans thousands of formats,
including many that no identification tool has ever heard of. Any approach that depends on
enumerating formats, or on a hand-written table mapping tool output to canonical names,
will cover a small fraction of the corpus and rot immediately.

**Corpus sizes vary by four orders of magnitude.** Some harnesses ship a single seed;
others ship tens of thousands. A rule tuned for one end behaves badly at the other.

## The core idea

Two questions are being asked, and they have different evidence requirements. Conflating
them into a single confidence threshold is the mistake that most naive versions make.

> **Is this corpus one format?** This is a question about *agreement between independent
> observers*. If libmagic, a machine-learning classifier, and the filename extension
> independently point at PDF, that is strong evidence even from a single seed.
>
> **Is this corpus several formats?** This is a question about *sample size*. You cannot
> discover that a corpus is mixed from two seeds, no matter how much the tools agree about
> those two seeds. Only seed count buys this.

So the algorithm has two independent gates: cross-source corroboration decides confidence
in a single-format verdict, and seed count decides whether a multi-format verdict may be
asserted at all. Neither gate substitutes for the other.

One further rule shapes everything below: **the code never looks inside a label.** It does
not tokenise, split, lowercase, strip prefixes or compare substrings. Every tool output is
an opaque symbol, and the only knowledge the program holds is a short list, per tool, of
the outputs that mean *"I have nothing to say"*. Everything else — which labels are
synonyms, which extensions carry no information, what to call a format — is derived from
the corpus. This is not purism. Each of those string operations was tried, and each one
introduced a specific class of error documented below.

## Step 1: Gather independent evidence

Every seed is described from several angles. What matters is not how many *outputs* there
are but how many *independent* ones.

| observer | evidence |
| --- | --- |
| filename | the seed's extension |
| libmagic | MIME type |
| magika | ML-based content classification |
| siegfried | PRONOM format identification |

Each observer gets a small null list of outputs that mean *"nothing to say"* — missing
extensions, catch-all unknowns, empty files, undifferentiated plain text, and similar
non-answers. These are discarded rather than treated as labels. The list says which
outputs are silence, not what any format is; the concrete values live in the code, not
here. Treating undifferentiated plain text as silence matters: a text format only
contributes when an observer names it more specifically than "plain text".

Two libmagic outputs are deliberately **not** used. Its `--extension` guess was only ever
useful as an alias source, and aliases are now derived. Its human-readable description is
discussed under "What was tried and rejected"; it is still recorded in the profile, because
re-profiling costs hours, but it does not label anything.

## Step 2: Learn which labels mean the same format

The observers speak different languages: libmagic says `application/x-tar`, the filename
says `.tar`, siegfried says *Tape Archive Format*. To detect agreement we must know when
two labels mean the same thing, without writing that knowledge down and without inspecting
the strings.

Where the labels *land* supplies it. Two labels denote one format when they fall on the
same seeds — specifically, when **restricted to the seeds where both observers spoke**,
each label predicts the other:

```
n(a, b) >= MIN_PAIR
n(a, b) / n(a, B spoke) >= THETA        and        n(a, b) / n(b, A spoke) >= THETA
```

Conditioning on "both spoke" is the essential detail. Most `.xml` seeds are plain text to
libmagic, so an unconditional rate would reject `.xml` ~ `text/xml`; among the seeds
libmagic did recognise, the agreement is overwhelming.

This is robust to unreliable tools for a structural reason: a wrong identification pairs
one label with one other label on one seed, and for that to create a false synonym the
*same* wrong pairing has to recur across the whole corpus. Random errors scatter. The
result is a sharply bimodal signal — of 4,466 candidate pairs, 3,180 score below 0.1 and
473 above 0.9, with only 158 in the 0.4–0.6 valley. That separation is why the method
works, and its measurement is the honest justification for the threshold.

Three things fall out for free:

- **Aliases are derived.** `font/sfnt` ~ `ttf`, `application/vnd.ms-excel` ~ `.xls`,
  *Tagged Image File Format* ~ `.tif`, `.sol` ~ `solidity`.
- **Genericness is derived.** `.bin` links to nothing, because it predicts no single
  format. There is no list of uninformative extensions; there does not need to be one.
- **Namespace fragmentation disappears.** `html`, `text/html` and *Hypertext Markup
  Language* are members of one identity rather than three formats.

### Mutual preference, not just a threshold

A label may keep only its **strongest partner within each other observer**. Without this
rule one systematically wrong tool fuses two real formats: libmagic calls Solidity sources
`application/javascript` often enough to clear the threshold (0.42), which merges
`.sol`/`solidity` into `.js`/`javascript` and mislabels every Solidity harness. Since
`application/javascript` prefers `.js` by a wide margin, requiring the preference to be
*mutual* drops that edge and keeps the correct `.sol` ~ `solidity` one.

This matters more than the threshold does. Mutual preference fixes the Solidity merge
identically at THETA 0.4, 0.5 and 0.6, whereas raising the threshold alone trades away
correct links elsewhere.

Connected components of the surviving relation are the format identities. Single linkage
is safe *only* because the relation is this strict: measured on the corpus it yields 314
identities of 2 to 8 members — usually one label per observer — rather than the transitive
blob that string similarity collapses into.

### Naming an identity

The component is the identity, so any member would serve as its name, but the choice is
visible in every report. Picking the commonest member alone names things badly: magika
calls FBX files `autohotkey`, and `autohotkey` outnumbers every other member of that class.

A label earns the right to name its class by tightly tracking at least one linked partner:
specificity is the share of its corpus-wide appearances that co-occur with its strongest
neighbour, and must reach `NAME_FLOOR`. Measuring against the single best partner, rather
than against the whole component, rejects scattershot labels (`magika:autohotkey` scores
0.01) without rewarding polysemous hubs that touch many members of a bridged component.
`sf:FBX (Filmbox) Text` scores 1.00. Among those that qualify, the commonest wins, which
keeps `application/json` from being renamed after glTF — a perfectly partner-specific but
very rare member of the JSON class.

## Step 3: Confirm seed by seed

A seed is **confirmed** as a format when two observers *with different sources* put
*directly linked* labels on **that seed** — a shared identity is not enough if the pair
was never an edge. Two outputs of one tool are not two opinions; they fail together.

Requiring agreement on the same seed is the single most important correctness property
here. The obvious alternative — compare what each observer says about the corpus as a
whole — lets a tool's false positives on a few dozen seeds corroborate an unrelated
majority computed over entirely different seeds. That is how a SQL corpus came to be
labelled `text/x-affix`, an XML corpus `image/svg+xml`, and a 140,000-seed rule corpus
`text/html` on the strength of 0.6% of it.

Seeds that confirm two identities at once are skipped. They are rare (3,405 of 806,693
confirmed seeds, 0.42%) and mostly show the relation being too conservative rather than
wrong: `.o` against `.so`, `.xlsm` against `.xlsx`, `html` against `xhtml+xml`.

## Step 4: Decide

1. **Multi-format**, if the corpus is large enough, most of it is confirmed, and two or
   more identities each hold a substantial minority. Checking this before any single-format
   claim matters, and it depends on step 2 having already merged the aliases: `.ttf`,
   `font/sfnt`, `magika:ttf` and *TrueType Font* must be one rival, not four.
2. **Single**, if one identity dominates the confirmed seeds and enough of them exist.
   This is the confident output.
3. **Single, unverified**, if nothing was confirmed but one observer is consistent across
   most of the corpus **and the label it used belongs to some identity**. Observers are
   tried in a fixed order (filename first), and the reported name is that observer's own
   label, not the identity's canonical name. The identity membership clause is a derived
   quality gate: it keeps `magika:crt` and `ext:tar` while dropping `ext:bin`,
   `ext:raw`, `magika:textproto` and `magika:go` — labels no other tool ever confirms
   anywhere in OSS-Fuzz, and therefore a tool's private vocabulary rather than a format.
   It is a filter and not a guarantee: `ext:txt` survives it on the strength of one
   spurious `['ext:txt', 'magika:lisp']` class, and is this tier's commonest label.
4. **Ambiguous**, if seeds were confirmed but no identity dominates.
5. **Unknown**, if no two observers agree on any seed.

Note what is deliberately absent: no rule discards a harness for having few seeds. A
one-seed corpus that three observers agree on is better evidence than a thousand-seed
corpus that only one tool can see into.

Two cleanup steps belong upstream. Harnesses that are build artifacts rather than real
fuzz targets should be dropped, and corpora that are byte-identical across projects are
decided identically anyway, since identical evidence yields identical verdicts.

## How it behaves

| verdict | harnesses | share | median seeds |
| --- | ---: | ---: | ---: |
| single | 794 | 22% | 37 |
| multi | 154 | 4% | 426 |
| single_unverified | 434 | 12% | 2 |
| ambiguous | 432 | 12% | |
| unknown | 1805 | 50% | |

794 confident verdicts span 173 distinct formats. Corroboration is usually broad rather
than marginal: 444 of them land on an identity that has members from all four observers
(confirmation itself only needs two), and the median confident harness has 99% of its
corpus confirmed.

On the one independent check available — the harness name often names its format, and the
algorithm never reads names — confident verdicts agree with the name 92% of the time,
against 84% for the previous string-matching version measured the same way, and that
measurement was computed generously for the old one. The residual disagreements are mostly
proxy artifacts rather than errors: `cairo/font_fuzzer` really does ship PNG seeds, and
`poppler/doc_fuzzer` really is PDF.

The large unknown fraction is a property of the data rather than a defect of the method.
For those harnesses, every tool reports noise for most seeds; the honest answer is that
the corpus does not say. The single most effective improvement is not a smarter rule but
wider tool coverage, since corroboration requires at least two observers to have looked.

## What was tried and rejected

Each of these was implemented and measured, not reasoned about.

**Comparing labels as strings.** Mechanically rewriting MIME subtypes (stripping
`application/x-` and `vnd.`) aligns the common cases but leaves everything siegfried names
in prose, so it needs an alias table and a stoplist of uninformative extensions beside it —
both hand-written, both open-ended. Derived linkage subsumes them: every alias worth
writing down turned out to be one it already finds, plus `.sol` ~ `solidity`, which a
hand-written table would likely have missed.

**Tokenising labels and linking on shared words.** This was the previous design. Words like
`file` and `object` become identity tokens, so *Hitachi SH COFF* corroborates *Canon SIF
File*; and taking the union of tokens across a group builds transitive bridges such as
`javascript` → `text/x-Algol68` → `lua`.

**libmagic's description as a fifth label.** Tested exactly as the design demands: raw,
unnormalized, sharing libmagic's source so it cannot corroborate the MIME type. It gains
145 confident verdicts and costs 12 points of precision (92% → 80%). The cause is
structural rather than incidental: `Composite Document File V2 Document, …` is a
*container* description that libmagic emits for every OLE2-based format, so it fuses
Bentley DGN, Corel Presentation, Microsoft Project and SSH public keys into one identity.
The formats it was supposed to rescue — UDF images, Outlook, HWP3, DirectDraw Surface,
MATLAB, 7-Zip — turn out to be recovered without it, by siegfried.

**Better similarity measures.** Dice, Jaccard and normalised PMI were compared against the
overlap coefficient over the 158 pairs in the ambiguous band. None of them separates it. At
the very top of the band, the wrong pair `magika:asm` ~ `application/x-wine-extension-ini`
scores 0.60/0.74/0.58/0.94 and the correct pair `audio/x-wav` ~ *Waveform Audio
(PCMWAVEFORMAT)* scores 0.60/0.75/0.60/0.95 — indistinguishable on all four. At the bottom,
the correct `.clj` ~ `text/x-clojure` and `.sgi` ~ `image/x-sgi` sit at exactly the same
0.40 as pairs that should not link. Dice and Jaccard are moreover rank-identical
(Kendall τ = 1.00), so they are one measure and not two. The discriminating information is
not in the score, so a more sophisticated score buys nothing.

**Fancier clustering.** Correlation clustering by greedy pivot gives 356 clusters against
320 from connected components, moves only 128 of 900 labels, and introduces 26 spurious
singletons. The relation is already a disjoint union of small near-cliques, so the
clustering algorithm is not where the difficulty lies — mutual preference is.

**Requiring identities to be coherent** (every cross-observer pair inside a class directly
linked) looked like a principled way to reject chains, but it flags 43 of 320 classes and
the great majority are correct classes where one tool pair simply overlaps weakly —
`.gz` ~ *GZIP Format* at 0.42, `.mp3` ~ `audio/mpeg` at 0.41. Pruning on it would drop
`.py` ~ `python` at 0.79. A missing edge usually means one tool was silent, not that the
labels differ.

**Requiring a pair to appear in two or more projects.** This correctly rejects
`.out` ~ `application/x-executable`, which is one project's habit, but costs 50 confident
verdicts (805 → 755) and collapses 320 identities to 229, with no measurable precision gain.
It also fails to catch the mid-band error it was aimed at, since `.rule` ~ `csv` appears in
two projects. Retained as `MIN_PROJ`, defaulted to 1.

## Tuned values

| parameter | value | basis |
| --- | --- | --- |
| `THETA` | 0.40 | how strongly two labels must predict each other; see the sweep below |
| `MIN_PAIR` | 3 | seeds carrying both labels before the relation is considered |
| `MIN_PROJ` | 1 | projects a pair must appear in; see above |
| `NAME_FLOOR` | 0.50 | share of a label's appearances that must co-occur with its strongest linked partner before it may name the class |
| `PURITY` | 0.80 | dominant share among a harness's confirmed seeds |
| `MIN_CONFIRMED` | 2 | confirmed seeds needed to claim a format, or the whole corpus if smaller |
| `MIN_SHARE` | 0.05 | share of the corpus that must be confirmed |
| `MULTI_FLOOR` | 0.15 | minority share needed to count as a second format; the only multi knob with real effect — 0.10 gives 176 multi verdicts, 0.15 gives 152, 0.25 gives 103 |
| `MULTI_MIN_SEEDS` | 2 | seeds a minority format needs; raising it to 3 moves 4 harnesses |
| `MULTI_MASS` | 0.50 | confirmed share before "several formats" is assertable |
| `MIN_SEEDS_MULTI` | 8 | corpus size before the question may be asked; sweeping 4 → 32 moves multi 155 → 130 and single by 2 |
| `UNVERIFIED_MASS` | 0.50 | corpus a lone observer must have seen before its unchecked word is reported |

The multi-format thresholds used to be delicate and no longer are: per-seed confirmation
already excludes the sparse false positives that previously drove spurious multi verdicts,
so the seed-count gates have little left to reject. `MULTI_FLOOR` is the only one worth
tuning.

Below `MIN_SEEDS_MULTI`, genuinely mixed corpora are labelled single. That is a real
compromise, but the alternative — refusing to label small corpora at all — is worse: a
cutoff at 5 seeds discards 174 of 805 confident verdicts, 85 of which have *all four*
sources agreeing, and eliminates 29 formats for which OSS-Fuzz holds no other evidence
(ARJ, Canon RAW, AC-3, Outlook PST, Snoop capture, …). Seed count was never what
distinguished the good labels from the bad.

`THETA` moves recall and barely moves precision, which is the clearest evidence that the
similarity signal is bimodal — there is little in the valley for the threshold to sort:

| THETA | 0.3 | 0.4 | 0.5 | 0.6 | 0.7 |
| --- | ---: | ---: | ---: | ---: | ---: |
| confident verdicts | 881 | 805 | 787 | 759 | 720 |
| formats | 179 | 175 | 175 | 172 | 163 |
| name-proxy precision | 92% | 92% | 91% | 92% | 94% |

0.40 is therefore a conservative default rather than an optimum: 0.30 labels 76 more
harnesses at the same measured precision, and 0.70 buys two points for 85 labels. This is
the knob to reach for in either direction; `MIN_PROJ` is the other.
