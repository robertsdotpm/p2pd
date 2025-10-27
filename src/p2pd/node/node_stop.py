import asyncio

# Shutdown the node server and do cleanup.
async def node_stop(node):
    # Make the worker thread for punching end.
    node.punch_queue.put_nowait(None)
    if node.punch_worker_task is not None:
        node.punch_worker_task.cancel()
        node.punch_worker_task = None

    # Stop sig message dispatcher.
    node.sig_msg_queue.put_nowait(None)
    if node.sig_msg_queue_worker_task is not None:
        node.sig_msg_queue_worker_task.cancel()
        node.sig_msg_queue_worker_task = None

    # Close other pipes.
    pipe_lists = [
        node.signal_pipes,
        node.tcp_punch_clients,
        node.turn_clients,
        node.pipes,
    ]

    for pipe_list in pipe_lists:
        for pipe in pipe_list.values():
            if pipe is None:
                continue

            if isinstance(pipe, asyncio.Future):
                if pipe.done():
                    pipe = pipe.result()
                else:
                    continue
                    
            await pipe.close()

    # Try close the multiprocess manager.
    """
    Node close will throw: 
    Exception ignored in: <function BaseEventLoop.__del__
    with socket error -1

    So you need to make sure to wrap coroutines for exceptions.
    
    """

    # Stop node server.
    await super().close()
    await asyncio.sleep(.25)