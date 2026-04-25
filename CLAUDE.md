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

## Writing tests

**Never use pytest-specific code.** All tests use `unittest` with `AsyncTestCase` from `aionetiface.testing`.

### The required pattern

```python
import unittest
from aionetiface.testing import AsyncTestCase

class TestMyFeature(AsyncTestCase):
    async def asyncSetUp(self):
        # async setup — runs before each test
        self.node = await start_something()

    async def asyncTearDown(self):
        # async teardown — runs after each test
        await self.node.close()

    async def test_something(self):
        result = await self.node.do_thing()
        self.assertEqual(result, expected)

    async def test_skip_example(self):
        if condition:
            self.skipTest("reason")
        ...
```

### Rules

- Base class is always `AsyncTestCase` — never `unittest.TestCase`, `unittest.IsolatedAsyncioTestCase`, or any pytest class.
- Test methods are `async def` coroutines — the backport handles them on Python 3.5–3.7.
- Use `self.skipTest("reason")` — never `pytest.skip(...)`.
- Never import `pytest`. Never use `@pytest.mark.*` decorators.
- `aionetiface.testing` calls `aionetiface_setup_event_loop()`, applies the linecache no-op, and opens the Windows firewall rule automatically when imported. No conftest.py setup needed.

### Running tests

Pull all four repos first:

```cmd
cd C:\Users\<user>\projects\p2pd && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\aionetiface && git fetch origin && git reset --hard origin/ai_experiment
cd C:\Users\<user>\projects\namebump && git fetch origin && git reset --hard origin/main
cd C:\Users\<user>\projects\sidewire && git fetch origin && git reset --hard origin/main
```

Run with `unittest discover` (sequential, reliable):

```sh
python -m unittest discover -s tests -p "test_*.py" -v
```

On Windows:

```cmd
C:\Users\<user>\.pyenv\pyenv-win\versions\3.8.6\python.exe -m unittest discover -s tests -p "test_*.py" -v
```

### asyncio debug mode

Never call `loop.set_debug(True)`. `IsolatedAsyncioTestCase` (Python 3.8+) sets it automatically, but `aionetiface.testing` neutralises the linecache overhead with a no-op patch.

### Install quirks (Python 3.5)

`setuptools>=68` uses Python 3.8+ syntax. On Python 3.5, bypass the build system:

```sh
pip install wheel "setuptools<50"
pip install --no-build-isolation --no-deps -e .
pip install --no-build-isolation --no-deps -e ../aionetiface
pip install --no-build-isolation --no-deps -e ../namebump
pip install --no-build-isolation --no-deps -e ../sidewire
```

On Python 3.5.0 specifically:

```sh
pip install "pathlib2==2.2.1" "pytest==4.6.11"
```
