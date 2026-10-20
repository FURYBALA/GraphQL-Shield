"""Lets the repository-level pytest run collect these tests: the gateway's packages
(gateway, backend, common, attacks, eval) are imported relative to this folder."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
