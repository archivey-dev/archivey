## 1. Merge queue

- [x] 1.1 `scripts/ci_scope.py` and the `Queue scope` job in `ci.yml`: a group that changes no library, test, dependency or CI path skips `test-queue`, `unar-distro-packages`, `pypy` and `atheris`
- [x] 1.2 The short Atheris requirement covers only the groups that change one of those paths

## 2. Tests

- [x] 2.1 `tests/test_ci_scope.py`: the path rule, the output line, the listed paths, and the wiring of the four jobs and the gate
