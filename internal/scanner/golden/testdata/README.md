# Golden corpus

Regression fixtures for the built-in scanners. Layout:

```
testdata/
└── <scanner>/                # pii, secrets, sqli, code
    ├── positive/
    │   ├── <name>.txt        # body fed to the scanner
    │   └── <name>.json       # expected findings
    └── negative/
        └── <name>.txt        # body that must produce zero findings
```

## Adding a positive fixture

1. Drop the body into `<scanner>/positive/<name>.txt`.
2. List the findings you expect in `<scanner>/positive/<name>.json`:

   ```json
   {
     "comment": "optional: explain what this fixture covers",
     "findings": [
       {"type": "secret.aws_access_key_id", "match": "AKIAIOSFODNN7EXAMPLE"}
     ]
   }
   ```

   - `type` matches the `Finding.Type` the scanner emits.
   - `match` is the literal substring of the body the scanner should report. The runner finds it in the body and verifies a `Finding` of the same `type` overlaps that range.
   - Alternatively, provide explicit `start` and `end` byte offsets.

You can list every finding you expect *of the listed types*. Extra findings from other types are allowed — the runner only checks that the expectations are satisfied. To enforce stricter behavior (e.g. no unrelated findings), prefer a negative fixture under the relevant scanner.

## Adding a negative fixture

Drop the body into `<scanner>/negative/<name>.txt`. No sidecar. The runner asserts the *scanner that owns the folder* emits no findings. Other scanners may still fire on the same body — that's fine.

## Running

```
go test ./internal/scanner/golden/...
go test -v ./internal/scanner/golden/...   # prints per-detector precision/recall
```

The test fails on any expected finding that didn't fire (false negative) or any finding in a negative fixture (false positive). Both move the precision/recall numbers in the summary table.

## What to add

The corpus is small on purpose — it's the starting point for the feedback loop, not the destination. Good additions:

- Real-world fixtures captured from past traffic (with secrets rotated and PII masked).
- Edge cases the scanner currently handles poorly (mark with a sidecar comment).
- Format variants for existing detectors (different separators, encodings, surrounding context).
- Adversarial inputs that try to break the rules (whitespace, encoding tricks).

Aim for diversity over volume. Two hundred well-chosen fixtures beat two thousand near-duplicates.
