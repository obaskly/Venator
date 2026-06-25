"""Pre-report validation pass.

Bug bounty triage lives or dies on signal-to-noise. Before anything reaches the
report, this stage re-confirms findings against the live target, detects
soft-404s (the #1 source of false 'exposed path' findings), de-duplicates, and
separates likely false positives from confirmed signals — all non-destructively
(extra GETs only). Nothing here exploits; it only re-observes.
"""
