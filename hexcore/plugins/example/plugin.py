"""HEXCORE example plugin — read-only, no sensitive permissions."""


def count_strings_containing(analysis, term):
    return sum(1 for s in analysis.strings if term.lower() in s.lower())


def register():
    return {"tools": {"count_strings_containing": count_strings_containing}, "rules": []}
