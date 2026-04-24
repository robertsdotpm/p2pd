# p2pd — project instructions

## Python compatibility

`requires-python = ">=3.5"` is intentional and must not be changed. Do not raise the minimum Python version under any circumstances.

## String formatting

Never use f-string literals (`f"..."`). They require Python 3.6+ and break the 3.5 constraint. Use `.format()` or import and use `fstr(template, args_tuple)` from `aionetiface.utility.utils`:

```python
"value is {}".format(val)
fstr("value is {0}", (val,))
```

## Naming

Never use leading-underscore names for variables, attributes, methods, or functions (e.g. no `_foo`, `_cancel_tasks`, `_private`). Use plain names. The single exception is dunder names (`__init__`, `__all__`, etc.) which are required by Python itself.

## Print statements

Never remove or comment out `print()` calls. They are intentional debugging and observability hooks — leave them exactly as found.

## Error handling

- Use `ValueError` for invalid input at API boundaries.
- Use `AssertionError` (or bare `assert`) for internal invariants that should never be false.
- Do not use `RuntimeError` as a catch-all for invariant violations.
- Do not use `ast.literal_eval` on user-supplied input — parse it explicitly.
- Pick one error idiom per function: either return a sentinel value or raise — not both.

## Running tests

Before running tests on any machine, always pull all four sibling repos to get the latest fixes. On Windows, use `git fetch && git reset --hard origin/ai_experiment` rather than `git pull` to avoid stale-file conflicts from manual SCP operations:

```cmd
cd C:\Users\<user>\projects\p2pd && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\aionetiface && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\namebump && git fetch origin && git reset --hard origin/main
cd C:\Users\<user>\projects\sidewire && git fetch origin && git reset --hard origin/main
```

Always run with pytest-xdist for parallel execution and `--timeout=90` to prevent hung network tests from blocking the session forever. Use Python 3.5 from pyenv so breakage on the minimum supported version is caught immediately:

```sh
~/.pyenv/versions/3.5.10/bin/python -m pytest tests/ -n auto --dist=loadfile --timeout=90 -q
```

On Windows (pyenv-win), use the versioned python.exe directly:

```cmd
C:\Users\<user>\.pyenv\pyenv-win\versions\<ver>\python.exe -m pytest tests/ -n auto --dist=loadfile --timeout=90 -q
```

## Test dependencies

These packages are required to run the test suite but are not package dependencies. Install them separately:

```text
pytest-xdist     # parallel workers (-n auto --dist=loadfile)
pytest-timeout   # per-test timeout (--timeout=90) — without this, hung network tests block forever
```

```sh
pip install pytest-xdist pytest-timeout
```

### Python 3.5 install quirks

`setuptools>=68` uses Python 3.8+ syntax (walrus operator). On Python 3.5, bypass the build system:

```sh
pip install wheel "setuptools<50"
pip install --no-build-isolation --no-deps -e .
```

The following sibling repos must be installed from their **local checkouts** using the same flags — do **not** let pip pull them from PyPI (the PyPI versions may be stale or incompatible):

```sh
pip install --no-build-isolation --no-deps -e ../aionetiface
pip install --no-build-isolation --no-deps -e ../namebump
pip install --no-build-isolation --no-deps -e ../sidewire
```

### Python 3.5.0 specifically (not 3.5.1+)

`typing.Type` was added in Python 3.5.3. Packages importing it crash on 3.5.0. Pin these:

```sh
pip install "pathlib2==2.2.1" "pytest==4.6.11" "pytest-xdist==1.34.0"
```

If pip was accidentally upgraded past 21.x on a 3.5.0 interpreter, restore it first:

```sh
python -m ensurepip
python -m pip install "pip==20.3.4" "setuptools<50"
```
