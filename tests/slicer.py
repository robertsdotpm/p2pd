import platform
from p2pd.test_init import *
from p2pd.utils import *
from p2pd.net import VALID_AFS
from p2pd.win_netifaces import *

from toxiclient import *
from toxiserver import *

class ToxicSlicer(ToxicBase):
    def set_params(self, avg_size, size_var, delay):
        self.avg_size = avg_size
        self.size_var = size_var
        self.delay = delay
        return self
    
    def chunk_old(self, start, end):
        """
        Base case:
        If the size is within the random variation,
        or already less than the average size, just
        return it. Otherwise split the chunk in about
        two, and recurse.
        """
        seg_len = end - start
        if seg_len - self.avg_size <= self.size_var:
            return [start, end]

        mid = int(start + (seg_len / 2))
        if self.size_var > 0:
            rand_len = rand_rang(0, (self.size_var * 2) + 1)
            mid += rand_len - self.size_var
            #mid = min(max(mid, start), end)

        # Recursion limit.
        left = self.chunk(start, mid)
        right = self.chunk(mid, end)

        return left + right
    
    def chunk(self, start, end):
        """
        Base case:
        If the size is within the random variation,
        or already less than the average size, just
        return it. Otherwise split the message into
        chunks of average size +/- size variation.
        """
        offsets = []
        seg_len = end - start
        if seg_len - self.avg_size <= self.size_var:
            return [start, end]
        
        # Build chunk offset list.
        # End offset overlaps with start offset.
        # This is not a mistake.
        p_start = start
        no = int(seg_len / self.avg_size)
        for _ in range(no):
            # Calculate a random variation.
            # May be positive or negative.
            rand_len = rand_rang(0, (self.size_var * 2) + 1)
            change = rand_len - self.size_var

            # Increase start pointer by random variation.
            p_end = p_start + (self.avg_size + change)

            # Record the chunk offsets.
            offsets += [p_start, min(p_end, end)]

            # Reached the end of the message size.
            if offsets[-1] == end:
                return offsets

            # Increase pointer for next segment.
            p_start = offsets[-1]

        return offsets

    async def run(self, msg, dest_pipe):
        offsets = self.chunk(0, len(msg))
        if self.delay:
            await asyncio.sleep(self.delay / 1000)

        for i in range(1, len(offsets), 2):
            chunk = msg[offsets[i-1]:offsets[i]]
            if self.delay:
                await asyncio.sleep(self.delay / 1000)

            #await dest_pipe.send(chunk)
            print(chunk)

class TestSlicer(unittest.IsolatedAsyncioTestCase):
    async def test_slicer(self):
        print("in test slicer.")
        msg = b"this is a sample message to slice."
        slicer = ToxicSlicer().set_params(
            avg_size=4,
            size_var=2,
            delay=10
        )

        await slicer.run(msg, None)




if __name__ == '__main__':
    main()
