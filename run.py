import os
import sys

# Get absolute path to src directory
src_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'src'))
sys.path.insert(0, src_path)

from main import main

if __name__ == "__main__":
    main()