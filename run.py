import os
import sys

src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
sys.path.insert(0, src_path)

from main import CipherCLI

if __name__ == "__main__":
    try:
        app = CipherCLI()
        app.run()
    except KeyboardInterrupt:
        print("\n\nExiting...")
