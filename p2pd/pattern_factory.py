import asyncio
from .utils import *

"""
Consensus first-in:
    - Concurrent exec of f() -> r
    - return when m * 2
    - or timeout: return most frequent r
"""
async def concurrent_first_agree_or_best(min_agree, tasks, timeout):
    results = {} # val[n]
    try:
        # Return as soon as agree on result.
        for task in asyncio.as_completed(tasks, timeout=timeout):
            result = await task
            results.setdefault(result, 0)
            results[result] += 1
            if results[result] >= min_agree:
                return result
    except asyncio.TimeoutError:
        # Return result with most agreement.
        best = None
        for value in results:
            if best is None:
                best = value
                continue

            if results[value] > results[best]:
                best = value
                continue

        return best
    
