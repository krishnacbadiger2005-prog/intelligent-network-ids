import importlib
import os
import sys

try:
    from netsniff_app.server import main
except ImportError:
    sys.path.insert(0, os.path.dirname(__file__))
    main = importlib.import_module("server").main


if __name__ == "__main__":
    main()


#PS C:\Users\Krishna Badiger\OneDrive\Desktop\FNETSNIFF> py -3.13 -m venv .venv
#PS C:\Users\Krishna Badiger\OneDrive\Desktop\FNETSNIFF> py -3.13 -m venv .venv
# >> .\.venv\Scripts\Activate.ps1
#(.venv) PS C:\Users\Krishna Badiger\OneDrive\Desktop\FNETSNIFF> python netsniff.py
#NetSniff IDS running at http://127.0.0.1:8000
#Install Npcap and run this terminal as Administrator for live packet capture.
#Use Ctrl+C to stop.

