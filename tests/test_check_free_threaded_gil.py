"""The free-threaded CI job's GIL check reads the extra it is meant to check."""

from __future__ import annotations

from tests.check_free_threaded_gil import extra_requirements


def test_extra_requirements_keeps_only_the_named_extra() -> None:
    requires = [
        'cryptography>=43; extra == "free-threaded"',
        'backports.zstd>=1.0.0; python_version < "3.14" and extra == "free-threaded"',
        'pyppmd>=1.3.1; extra == "recommended"',
        "plain>=1",
    ]
    assert extra_requirements(requires, "free-threaded") == [
        ("cryptography", ' extra == "free-threaded"'),
        ("backports-zstd", ' python_version < "3.14" and extra == "free-threaded"'),
    ]
