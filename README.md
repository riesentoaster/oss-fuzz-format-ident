# Identify OSS-Fuzz harness input formats

Downloads public seed corpora, profiles them with libmagic / magika / siegfried,
and labels each harness's input format. See [`ALGORITHM.md`](ALGORITHM.md).

## Docker

```bash
docker build -t identify-harnesses .
docker run --rm -ti -v "$PWD/data:/work/data" identify-harnesses
```

All outputs land in `data/`:

| Step     | Output                            |
|----------|-----------------------------------|
| download | `seed_corpora/`                   |
| profile  | `raw_seeds.jsonl`                 |
| identify | `identified.json`, `formats.json`, `mapped_formats.json` |

Run one step with `--steps download|profile|identify`. Useful flags: `--max-projects N`, `--workers N`, `--outdir DIR`.
