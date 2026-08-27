# Contributing to Subwatch

Thanks for helping improve Subwatch. Bug reports, documentation fixes, tests, and focused feature proposals are welcome.

## Development setup

1. Fork and clone the repository.
2. Create a virtual environment with Python 3.10 or newer.
3. Run `pip install -e '.[dev]'`.
4. Make a focused change and add tests where behavior changes.
5. Run `pytest` and `python -m compileall -q src`.
6. Open a pull request describing the problem, approach, and verification.

Please keep dependencies lean and avoid features that perform intrusive scanning, bypass access controls, or weaken the existing network safeguards. By contributing, you agree that your contribution is licensed under the MIT License.
