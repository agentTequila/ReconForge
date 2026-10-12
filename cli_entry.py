"""PyInstaller-friendly CLI entrypoint.

Build: pyinstaller --onefile --console --icon assets/icon.ico --name reconforge-cli cli_entry.py
"""

from reconforge.cli import main

if __name__ == "__main__":
    main()
