import functools
import asyncio
import re
import time
import binascii
import ipaddress
import sys, os
import ctypes
import platform
import logging
import traceback
import random
import inspect
#import uvloop
import itertools
import ctypes
import urllib.parse
import platform
import selectors
import copy

# Yoloswaggins.
if not hasattr(asyncio, 'create_task'):
    asyncio.create_task = asyncio.ensure_future

vmaj, vmin, _ = platform.python_version_tuple()
vmaj = int(vmaj); vmin = int(vmin)
if vmaj < 3:
    raise Exception("Python 2 not supported.")
if vmin < 8:
    if sys.platform == 'win32':
        #raise Exception("Windows needs Python 3.8 or higher.")
        pass
if vmin < 5:
    raise Exception("Non-Windows OS needs Python 3.5 or higher")

def proactorfy(self=None):
    """
    The func is called once to set the main event loop
    to use. At this point there is an existing event loop
    not doing anything. This event loop should be used first
    rather than creating a new one. With aiounittest this
    prevents having unclosed event loops at the end of
    running test suites.
    """
    try:
        loop = asyncio.get_event_loop()
    except:
        loop = asyncio.ProactorEventLoop()

    asyncio.set_event_loop(loop)
    if self is not None:
        self.my_loop = loop
        return self.my_loop

    return loop

if sys.platform == 'win32':
    # Won't work on older Python < 3.6.
    try:
        proactorfy()

        # Only available on later Python versions.
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    except Exception:
        pass

if "P2PD_DEBUG" in os.environ: 
    IS_DEBUG = 1
    logging.basicConfig(
        filename='program.log',
        level=logging.DEBUG,
        format='[%(asctime)s.%(msecs)03d] @ [%(filename)s:%(lineno)d] %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    def log(m):
        if "P2PD_DEBUG" not in os.environ:
            return

        logging.info(m)
else:
    IS_DEBUG = 0
    log = lambda m: 1


STATUS_RETRY = 1
STATUS_SUCCESS = 2
STATUS_FAILURE = 3
MAX_PORT = 65535
_COPY          = ctypes.pythonapi._PyUnicode_Copy
_COPY.argtypes = [ctypes.py_object]
_COPY.restype  = ctypes.py_object

re.unescape = lambda x: re.sub(r'\\(.)', r'\1', x)
to_b = lambda x: x if type(x) == bytes else x.encode("ascii")
to_s = lambda x: x if type(x) == str else x.decode("ascii")
to_hs = lambda x: to_s(binascii.hexlify(to_b(x)))
to_h = lambda x: to_hs(x) if len(x) else "00"
to_i = lambda x: x if isinstance(x, int) else int(x, 16)
to_n = lambda x: x if isinstance(x, int) else int(to_s(x), 10)
i_to_b = lambda x, o='big': x.to_bytes((x.bit_length() + 7) // 8, o)
b_to_i = lambda x, o='big': int.from_bytes(x, o)
valid_port = lambda p: p >= 1 and p <= MAX_PORT
port_wrap = lambda p: (p % MAX_PORT) or 1
to_unique = lambda x: [i for n, i in enumerate(x) if i not in x[:n]]
ip_f = ipaddress.ip_address
class_name = lambda x: type(x).__name__ if inspect.isclass(x) else None
timestamp = lambda p=0: time.time() if p else int(time.time())
strip_none = lambda x: [i for i in x if i]
neg_flip = lambda r, x, y: -r if x > y else r
n_dist = lambda x, y: neg_flip(max(x, y) - min(x, y), x, y)
dict_plus = lambda d, k: d[k] if k in d else 0
rand_rang = random.randrange
list_join = lambda l: list(itertools.chain.from_iterable(l))
from_range = lambda r: rand_rang(r[0], r[1] + 1)
in_range = lambda x, r: x >= r[0] and x <= r[1]
b_and = lambda abytes, bbytes: bytes(map(lambda a,b: a & b, abytes, bbytes))
b_or = lambda abytes, bbytes: bytes(map(lambda a,b: a | b, abytes, bbytes))
len_range = lambda r: r[1] - r[0]
get_bits = lambda n, l, p=0: ( ((1 << l) - 1)  &  (n >> p ) )
actual_copy = _COPY
is_no = lambda x: to_s(x).isnumeric()
is_b = lambda x: isinstance(x, bytes)
rm_whitespace = lambda x: re.sub(r"\s+", "", x, flags=re.UNICODE)
urlencode = lambda x: to_b(urllib.parse.quote(x))
urldecode = lambda x: to_b(urllib.parse.unquote(x))

# Take a dict template called Y and a child dict called X.
# Yield a new dict with Y's vals overwritten by X's.
def dict_child(x, y):
    out = copy.deepcopy(y)
    for key in x:
        out[key] = x[key]
    #
    return out

def dict_merge(x, y):
    x.update(y)
    return x

def rand_plain(n):
    charset =  b"012345678abcdefghijklmnopqrs"
    charset += b"tuvxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    buf = b""
    for meow in range(0, n):
        ch = random.choice(charset)
        buf += bytes([ch])
        
    return buf

def ensure_resolved(targets):
    if not isinstance(targets, list):
        targets = [targets]

    for i, target in enumerate(targets):
        if not target.resolved:
            e = "Target offset = {}, id = {}, type = {} not resolved".format(
                i,
                id(target),
                type(target)
            )

            raise Exception(e)

def sorted_search(n_list, i, start_at=None):
    # Make sure list entries exist.
    list_len = len(n_list)
    if not list_len:
        return None

    # [2, 2, 2, 2] even -> index 2 -> right of a pair.
    # [1, 2, 3] odd -> index 1 -> middle, odd one out.
    x = 0
    if start_at is None:
        start_index = int(list_len / 2)
    else:
        start_index = start_at % list_len

    # Find nearest number.
    while x < list_len:
        # Avoid underflow.
        if start_index <= 0:
            return 0

        # X >= i: (match or decrease) by half
        # else < i: (increase) by half
        if n_list[start_index] >= i:
            if n_list[start_index - 1] < i:
                return start_index
            else:
                start_index -= int(start_index / 2) or 1
        else:
            start_index += int(start_index / 2) or 1

        # Reached the end.
        if start_index >= list_len - 1:
            return list_len - 1

        # If items aren't sorted an infinite loop may be possible.
        x += 1

    raise Exception("Sorted search: List may not be sorted.")

async def threshold_gather(tasks, f_filter, t):
    # Do tests concurrently.
    results = await asyncio.gather(*tasks)
    results = strip_none(results)
    results = sorted(f_filter(results))
    if not len(results):
        return None

    # Return first result that satisfies threshold.
    count = 0
    cur = results[0]
    for i in range(0, len(results)):
        if results[i] == cur:
            count += 1
        else:
            count = 1
            cur = results[i]

        if count >= t:
            return cur

    # Threshold requirement not met.
    return None

"""
https://stackoverflow.com/questions/843828/how-can-i-check-hamming-weight-without-converting-to-binary
"""
def hamming_weight(n: int) -> int:
    c = 0
    while n:
        c += 1
        n &= n - 1

    return c

def bits_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')

def range_intersects(a, b):
    # If ranges are the same they intersect.
    if a == b:
        return True

    # Make a list of the ranges and make the pairs ascend.
    # Then make a list of all the elements together.
    range_list = sum(sorted([a, b]), [])
    return range_list[2] <= range_list[1]

def intersect_range(a, b):
    # Add all the elements together.
    els = sum([a, b], [])

    # Sort from small to large.
    asc = sorted(els)

    # Middle two els == intersect range.
    return [asc[1], asc[2]]

def rand_b(n):
    buf = b""
    for i in range(0, n):
        buf += bytes([rand_rang(256)])

    return buf

def rand_b_readable(n):
    chars = b"abcdefghijklmnopqrstuvwxyz"
    chars += b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    chars += b"0123456789 "

    buf = b""
    for _ in range(n):
        buf += bytes([random.choice(chars)])

    return buf

def field_wrap(n, field):
    start_range, stop_range = field
    stop_range += 1
    y = x = n % stop_range
    while 1:
        if x < start_range:
            x += start_range
            y = x % stop_range
            if x != y:
                x = y
        #
        if x == y:
            break
    #
    return x

def field_dist(x, y, field):
    # Get distance between numbers.
    max_no = max(x, y)
    min_no = min(x, y)
    ret = dist = max_no - min_no

    # They are the same value.
    if not dist:
        return 0

    # min is closer to the start of the field.
    rem = field - max_no
    field_dist = min_no + rem
    if field_dist < dist:
        ret = field_dist

    # Calculate sign of result.
    if x == min_no:
        return -ret
    else:
        return ret

def what_exception():
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    print(exc_type, fname, exc_tb.tb_lineno)
    print(traceback.format_exc())

def log_exception():
    exc_type, exc_obj, exc_tb = sys.exc_info()
    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
    exc_out = traceback.format_exc()
    log("> {}, line {} = {}".format(
        fname,
        exc_tb.tb_lineno,
        exc_out
    ))

async def async_wrap_errors(coro, timeout=None):
    try:
        # Don't bound wait time.
        if timeout is None:
            return (await coro)

        # Bound wait time.
        if isinstance(timeout, int):
            return (await asyncio.wait_for(coro, timeout))
    except Exception as e:
        # Log all errors.
        log_exception()

def sync_wrap_errors(f, args=[]):
    try:
        if len(args):
            return f(*args)
        else:
            return f()
    except Exception:
        # Log all errors.
        log_exception()

async def async_retry(gen, count, timeout=4):
    # Timeout counter and retry counter.
    i = r = 0
    while 1:
        # Wait for success or timeout.
        try:
            # Run main coroutine
            # get retry status and retry coro.
            init_coro = gen()
            status_future, retry_coro, new_future = await asyncio.wait_for(
                async_wrap_errors(init_coro),
                timeout
            )

            # Do first retry coroutine.
            if i == 0:
                await retry_coro()

            # Get return status after first retry.
            status = await asyncio.wait_for(status_future, timeout)

            # Overwrite old future so it can be set again.
            status_future = new_future()

            # Schedule another attempt.
            if status == STATUS_RETRY:
                i -= 1
                r += 1
                await retry_coro()

            # Success or failure.
            if status != STATUS_RETRY:
                return None

        # Timeout occured -- try again.
        except asyncio.TimeoutError:
            pass

        # Limit retries to no.
        finally:
            i += 1
            if count in (i, r):
                break

    raise asyncio.TimeoutError("Async retry timeout")

def rm_done_tasks(hey):
    pending_tasks = []
    for task in hey:
        if not task.done():
            pending_tasks.append(task)

    return pending_tasks

# Process return value.
def handler_done_builder(pipe, handler, task=None):
    def closure(result):
        # Remove task from pipe.
        if task in pipe.tasks:
            pipe.handler_tasks.remove(task)

        # Got an int result -- check if its error code.
        if isinstance(result, int):
            # Error code.
            if result:
                # Log the error.
                out = f"> {handler} = error {result}."
                log(out)

        # If it returns a task then save it.
        if isinstance(result, asyncio.Task):
            pipe.tasks.append(result)

    return closure

def run_handler(pipe, handler, client_tup, data=None):
    # It's async.
    if inspect.iscoroutinefunction(handler):
        # Lets you process messages from an async func.
        task = asyncio.create_task(
            async_wrap_errors(
                handler(data, client_tup, pipe)
            )
        )

        # Process result if anyone.
        task.add_done_callback(
            handler_done_builder(pipe, handler, task)
        )

        # Needed or they might be garbage collected.
        pipe.handler_tasks.append(task)
    else: 
        # It's a callback.
        result = sync_wrap_errors(
            handler, [data, client_tup, pipe]
        )

        # Process result if any.
        handler_done_builder(pipe, handler)(result)

# Used for event-based programming.
# Can execute code on new cons, dropped cons, and new msgs.
def run_handlers(pipe, handlers, client_tup, data=None):
    # Run any registered call backs on msg.
    pipe.handler_tasks = rm_done_tasks(pipe.handler_tasks)
    for handler in handlers:
        # Run the handler as a callback or coroutine.
        run_handler(pipe, handler, client_tup, data)

def run_in_executor(f):
    @functools.wraps(f)
    def inner(*args, **kwargs):
        if not inspect.iscoroutinefunction(f):
            loop = asyncio.get_event_loop()
            return loop.run_in_executor(None, lambda: f(*args, **kwargs))
        else:
            def helper():
                loop = asyncio.new_event_loop()
                try:
                    coro = f(*args, **kwargs)
                    asyncio.set_event_loop(loop)
                    return loop.run_until_complete(coro)
                finally:
                    loop.close()

            loop = asyncio.get_event_loop()
            return loop.run_in_executor(None, helper)

    return inner

# Wait for tasks to finish up until a timeout.
# Otherwise cancel them and wait for errors.
async def gather_or_cancel(tasks, timeout):
    try:
        await asyncio.wait_for(
            asyncio.gather(*tasks),
            timeout
        )
    except asyncio.TimeoutError:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks)
    except asyncio.CancelledError:
        pass
    finally:
        return []

class SelectorEventPolicy(asyncio.DefaultEventLoopPolicy):
    def new_event_loop(self):
        selector = selectors.SelectSelector()
        return asyncio.SelectorEventLoop(selector)

def selector_event_loop():
    selector = selectors.SelectSelector()
    return asyncio.SelectorEventLoop(selector)

def get_loop(loop=None):
    if loop is None:
        if sys.platform == "win32":
            loop = asyncio.ProactorEventLoop()
        else:
            loop = asyncio.get_event_loop()
    else:
        loop = loop()

    return loop

# Will be used in sample code to avoid boilerplate.
def async_test(f, args=[], loop=None):
    #uvloop.install()
    loop = get_loop(loop)
    #if IS_DEBUG:
    #    loop.set_debug(True)
    loop.set_debug(False)
    if len(args):
        loop.run_until_complete(f(*args))
    else:
        loop.run_until_complete(f())
    loop.close()

async def return_true(result=None):
    return True
            
# If there's an error that its already in a loop
# Run nest_asyncio.apply()
def async_to_sync(f, params=None, loop=None):
    loop = loop or get_loop()
    if params is not None:
        def closure(args):
            return loop.run_until_complete(f(*args))
            
        return closure
    else:
        def closure():
            return loop.run_until_complete(f())
            
        return closure

def get_running_loop():
    try:
        version = sys.version_info[1]
        if version >= 7:
            return asyncio.get_running_loop()
        else:
            return asyncio.get_event_loop()
    except RuntimeError:
        return None


if __name__ == "__main__": # pragma: no cover
    x = [1, 1]
    y = [2, 2]
    assert(range_intersects(x, y) == False)

    x = [1, 2]
    y = [2, 2]
    assert(range_intersects(x, y) == True)

    x = [1, 2]
    y = [1, 2]
    assert(range_intersects(x, y) == True)

    
    x = [1, 10]
    y = [5, 20]
    assert(range_intersects(x, y) == True)

    
