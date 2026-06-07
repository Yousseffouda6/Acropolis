# offensive/

This directory is a **pointer**. Acropolis's offensive work (Phase 5) is
documented as a full engagement writeup rather than as loose playbooks here:

- [`../writeups/phase-5-attack-detect.md`](../writeups/phase-5-attack-detect.md)
  — the attack/detect loop: SSH brute force, post-compromise host actions, and
  web-layer attacks launched from Kali against the live host, each hunted in the
  Wazuh SIEM stood up in Phase 4. Its headline finding: the real SQLi login
  bypass succeeded with **zero** alerts while a noisy scan raised ~7,000 —
  detection was inversely correlated with danger.

All testing was performed against the author's own lab, over a controlled
channel.
