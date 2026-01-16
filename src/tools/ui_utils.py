import tkinter as tk
from tkinter import filedialog
from typing import Optional

def browse_file(title: str = "Select File") -> Optional[str]:
    """Helper to open a file dialog."""
    try:
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        root.attributes('-topmost', True) # Bring to front
        file_path = filedialog.askopenfilename(title=title)
        root.destroy()
        return file_path if file_path else None
    except Exception as e:
        print(f"[!] GUI File selection failed: {e}")
        return None

def save_file_dialog(title: str = "Save Output As") -> Optional[str]:
    """Helper to open a save file dialog."""
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes('-topmost', True)
        file_path = filedialog.asksaveasfilename(title=title)
        root.destroy()
        return file_path if file_path else None
    except Exception as e:
        print(f"[!] GUI Save selection failed: {e}")
        return None
