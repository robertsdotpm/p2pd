import asyncio
from .utils import *

"""
Consensus first-in:
    - Concurrent exec of f() -> r
    - return when m * 2
    - or timeout: return most frequent r
"""
async def concurrent_first_agree_or_best(min_agree, tasks, timeout, wait_all=False):
    results = {}
    pending = set(tasks)
    try:
        for task in asyncio.as_completed(tasks, timeout=timeout):
            result = await task
            pending.discard(task)
            results[result] = results.get(result, 0) + 1
            if results[result] >= min_agree:
                return result
    except asyncio.TimeoutError:
        best = max(results, key=results.get, default=None)
        return best
    finally:
        if wait_all and pending:
            await asyncio.gather(*pending, return_exceptions=True)