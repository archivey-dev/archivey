"""Prototype ports of built-in readers to ``archivey.formats``, for speed comparison only.

Not registered by archivey itself. Each module registers its handler under a plugin
container, so a benchmark can open the same file with the built-in reader and the port.
"""
