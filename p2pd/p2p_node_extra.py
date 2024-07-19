import asyncio
from .settings import *
from .machine_id import get_machine_id, hashed_machine_id
from .tcp_punch import *
from .signaling import *
from .p2p_addr import *
from .p2p_utils import *
#from .p2p_pipe import *
from .p2p_defs import *

class P2PUtils():
    async def load_machine_id(self, app_id, netifaces):
        # Set machine id.
        try:
            return hashed_machine_id(app_id)
        except:
            return await fallback_machine_id(
                netifaces,
                app_id
            )
        
    async def load_signal_pipe(self, offsets, attempts=2):
        count = 0
        while not offsets.empty():
            count += 1
            if count >= attempts:
                return
            
            offset = await offsets.get()
            mqtt_server = MQTT_SERVERS[offset]
            signal_pipe = SignalMock(
                peer_id=to_s(self.node_id),
                f_proto=self.signal_protocol,
                mqtt_server=mqtt_server
            )

            try:
                await signal_pipe.start()
                self.signal_pipes[offset] = signal_pipe
                return
            except Exception:
                if signal_pipe.is_connected:
                    await signal_pipe.close()

                return None
        
    """
    There's a massive problem with the MQTT client
    library. Starting it must use threading or do
    something funky with the event loop.
    It seems that starting the MQTT clients
    sequentially prevents errors with queues being
    bound to the wrong event loop.
    
    TODO: investigate this.
    """
    async def load_signal_pipes(self):
        q = asyncio.Queue()
        serv_len = len(MQTT_SERVERS)
        offsets = shuffle(list(range(serv_len)))
        [q.put_nowait(o) for o in offsets]

        tasks = []
        for _ in range(SIGNAL_PIPE_NO):
            task = await self.load_signal_pipe(q)
            #tasks.append(task)

        #await asyncio.gather(*tasks)

    # Accomplishes port forwarding and pin hole rules.
    async def forward(self, port):
        tasks = []
        for server in self.servers:
            # Get the bind IP and interface for the route.
            route = server[0]

            # Only forward to public IPv6 addresses.
            ipr = IPRange(route.nic())
            if route.af == IP6 and ipr.is_private:
                continue

            # Make task to forward this route.
            task = route.forward(port)
            tasks.append(task)

        # Get a list of tasks to do forwarding or pin holes.
        results = await asyncio.gather(*tasks)
        tasks = []
        for result in results:
            if len(result):
                tasks += result

        # Now do that all at once since it might take a while.
        if len(tasks):
            await asyncio.gather(*tasks)

    def find_signal_pipe(self, addr):
        our_offsets = list(self.signal_pipes)
        for offset in addr["signal"]:
            if offset in our_offsets:
                return self.signal_pipes[offset]

        return None

    def rm_pipe_id(self, pipe_id):
        def closure(data, client_tup, pipe):
            # Delete reference to pipe.
            log(f"Running rm pipe id {pipe_id}")
            if pipe_id in self.pipes:
                del self.pipes[pipe_id]

        return closure

    def setup_multiproc(self, pp_executor, mp_manager):
        # Process pools are disabled.
        if pp_executor is None:
            self.pp_executor = None
            self.mp_manager = None
            return
            
        assert(mp_manager)
        self.pp_executor = pp_executor
        self.mp_manager = mp_manager

    def setup_coordination(self, sys_clock):
        self.sys_clock = sys_clock

    def setup_tcp_punching(self):
        self.tcp_punch_clients = [
            TCPPunch(
                interface,
                self.ifs,
                self,
                self.sys_clock,
                self.pp_executor,
                self.mp_manager
            )
            for interface in self.ifs
        ]

