---
name: Add a case
about: Propose a vulnerability class or variant the corpus should cover
title: "[case] "
labels: corpus
---

**Class**
An existing class, or a new one.

**The vulnerable case**
What the defect is and how an attacker reaches it.

**The safe twin**
Required. What differs, and why a scanner ought to be able to tell them apart. The twin should
share imports, tool names and the sink — differing only in whether the vulnerability is real.

**How the label is proved**
The payload, and the oracle string it produces. Payloads stay local and inert.
