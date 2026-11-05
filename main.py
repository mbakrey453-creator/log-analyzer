"""Launch the Intrusion Detection Log Analyzer web GUI.

    python main.py             # web GUI (HTML/CSS/JS) at http://127.0.0.1:8765
    python main.py 9000        # custom port

The classic tkinter GUI is still available:  python gui.py
"""

from server import main

if __name__ == "__main__":
    main()
