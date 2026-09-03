**What this changes**

**Checks**

- [ ] `python3 corpus/verify.py` passes — every label is still demonstrable
- [ ] `python3 -m pytest tests -q` passes
- [ ] New cases come in pairs, with a `proof` block in each
- [ ] New adapters declare `surfaces` and `languages` honestly, and report a crash as
      `ran=False` rather than as an empty result
