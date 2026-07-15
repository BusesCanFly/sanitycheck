# INERT ChocoPoC-lookalike fixture

This directory is a **safe, non-functional** decoy used to test chococheck's
detectors. It contains the *textual patterns* of the ChocoPoC campaign
(malicious package names, an import-shadowing `.so`, an install-time `setup.py`
hook, DoH/SNI-fronting strings, credential-harvest paths, a `.pth` shim, IOC
markers) but **executes nothing harmful** — the suspicious lines live inside
inert string constants and stub functions that are never called.

`chococheck.sh testdata/chocopoc-lookalike` should return **DANGEROUS**.
