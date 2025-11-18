from ....net.ip_range import *
from ....nic.nat.nat_utils import *
from ....nic.interface import *
from ....nic.nat.nat_predict import *
from ....utility.clock_skew import *
from .punch_defs import *
from .punch_process import *
from ....node.node_defs import *

async def setup_punch_coordination(node, sys_clock=None):
    node.max_punchers, node.pp_executor = await get_pp_executors()
    node.sys_clock = sys_clock

def add_punch_meeting(node, params):
    # Schedule the TCP punching.
    node.punch_queue.put_nowait(params)

async def schedule_punching_with_delay(node, pipe_id, n=2):
    await asyncio.sleep(n)

    # Ready to do the punching process.
    add_punch_meeting(
        node,
        [pipe_id]
    )

async def punch_queue_worker(node, puncher_cls):
    try:
        if shutdown_event.is_set():
            return

        params = await node.punch_queue.get()
        if params is None:
            return
        
        if len(params):
            pipe_id = params[0]
            if pipe_id in node.tcp_punch_clients:
                puncher = node.tcp_punch_clients[pipe_id]
                task = asyncio.create_task(
                    async_wrap_errors(
                        setup_punching_process(puncher, puncher_cls)
                    )
                )

                # Avoid garbage collection for this task.
                node.tasks.append(task)

        node.punch_worker_task = asyncio.create_task(
            punch_queue_worker(node, puncher_cls)
        )
    except asyncio.CancelledError:
        return
    except RuntimeError:
        log_exception()
        return
    except Exception:
        log_exception()
    
def start_punch_worker(node, puncher_cls):
    node.punch_worker_task = asyncio.create_task(
        punch_queue_worker(node, puncher_cls)
    )
