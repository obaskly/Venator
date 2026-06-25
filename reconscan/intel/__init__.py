"""Threat-intel enrichment (CVE -> exploitation guidance).

Turns a detected CVE into actionable, MANUAL next steps: public-exploit
references, PoC pointers, and CVSS/description context — without ever running an
exploit. Sources are local/offline-first (nuclei template metadata, optional
searchsploit) plus constructed reference URLs for manual follow-up.
"""
