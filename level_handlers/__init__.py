from .level0 import run as run0
from .level1 import run as run1
from .level2 import run as run2
from .level3 import run as run3
from .void import run as run_void
from .void_plus import run as run_void_plus
from .recon import run as run_recon

# Export a simple mapping for convenience used in main.py
handler_map = {
    "0": run0,
    "1": run1,
    "2": run2,
    "3": run3,
    "void": run_void,
    "void_plus": run_void_plus,
    "recon": run_recon,
}
