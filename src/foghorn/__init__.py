"""Foghorn package"""

# Re-export the plugins subpackage so dotted paths like 'foghorn.plugins.*'
# work with tooling that traverses attributes instead of using importlib.
from . import plugins as plugins
