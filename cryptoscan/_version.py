"""Single source of truth for the package version.

Kept in its own module so cbom.py / report.py / cli.py can import it without
creating an import cycle through the package __init__.
"""

__version__ = "0.2.6"
