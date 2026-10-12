"""PyInstaller-friendly GUI entrypoint.

Build: pyinstaller --onefile --windowed --icon assets/icon.ico --name ReconForge gui_entry.py
"""

from reconforge.gui import main

if __name__ == "__main__":
    main()
