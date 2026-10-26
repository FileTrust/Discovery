#!/usr/bin/env python3
"""Remove the installed runtime; purge requires a separate confirmation."""
import sys
from ft_package import main
if __name__ == '__main__':
    sys.argv.insert(1, 'uninstall')
    main()
