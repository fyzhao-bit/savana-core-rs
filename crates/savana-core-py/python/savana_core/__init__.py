from . import savana_core as _native
from .savana_core import *


def __getattr__(name):
    return getattr(_native, name)
