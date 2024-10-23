Installation
===============

P2PD is available on PyPI and Github. 

.. parsed-literal:: 
    python3 -m pip install p2pd

P2PD also comes with optional dependencies. These are required depending on
the functionality to be used. E.g. mysql packages to run a PNP server. There's
no harm in installing the extra dependencies.

.. parsed-literal:: 
    git clone https://github.com/robertsdotpm/p2pd.git
    cd p2pd
    python3 -m pip install -r requirements.txt
    python3 -m pip install -r optional-debug-requirements.txt
    python3 -m pip install -r optional-server-requirements.txt