Installation
===============

P2PD is available directly on PyPI and Github. 

.. parsed-literal:: 
    python3 -m pip install p2pd

P2PD also comes with optional dependencies. These are required depending on
additional functionality to be used. E.g. mysql clients to run a PNP server.

.. parsed-literal:: 
    git clone https://github.com/robertsdotpm/p2pd.git
    cd p2pd
    python3 -m pip install -r requirements.txt
    python3 -m pip install -r optional-debug-requirements.txt
    python3 -m pip install -r optional-requirements.txt
    python3 -m pip install -r pnp-server-requirements.txt