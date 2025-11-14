import asyncio
from collections import defaultdict
from .utils import *

"""
Consensus first-in:
    min_agree=2, max_agree=5, timeout=4 (tasks get 4, this func gets 5)
"""
async def concurrent_first_agree_or_best(min_agree, tasks, timeout, wait_all=False):
    results = defaultdict(int)
    pending = set(tasks)
    log(fstr("Con first agree: min={0}. task_no={1}, timeout={2}, wait_all={3}", 
            (min_agree, len(tasks), timeout, wait_all)
    ))

    def process_result(result):
        if result is None:
            return None
        
        results[result] += 1
        if results[result] >= min_agree:
            return result

    try:
        if wait_all:
            ret = await asyncio.wait_for(
                asyncio.gather(*pending, return_exceptions=True),
                timeout=timeout
            )
            
            for result in ret:
                winner = process_result(result)
                if winner is not None:
                    return winner
        else:
            for task in asyncio.as_completed(tasks, timeout=timeout):
                pending.discard(task)
                result = await task
                winner = process_result(result)
                if winner is not None:
                    return winner
                
    except asyncio.TimeoutError:
        pass

    # Return the most frequent result if min_agree wasn't reached
    if results:
        return max(results, key=results.get)
    