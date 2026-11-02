"""Collectors GET data; scanners ANALYZE it.

LESSON 20: In a real deployment nobody hands you files. A collector gathers
raw data (here: live syslog messages) and passes it to the same matching logic a
scanner uses. Keeping the two jobs separate means a new data source never
requires rewriting detection, and new detection never requires touching sources.
"""
