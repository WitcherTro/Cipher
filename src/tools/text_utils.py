from typing import Optional

def clean_text(text: str) -> str:
    """Remove non-alphabetic characters and convert to uppercase"""
    return ''.join(c.upper() for c in text if c.isalpha())

def is_valid_input(text: str) -> bool:
    """
    Check if input contains only letters and spaces
    Returns True if valid, False otherwise
    """
    return all(c.isalpha() or c.isspace() for c in text)

def format_text(text: str, block_size: int = 5) -> str:
    """
    Format text into blocks of specified size
    Example: "HELLO" -> "HELLO" with block_size=5
    """
    cleaned = clean_text(text)
    return ' '.join(cleaned[i:i+block_size] 
                   for i in range(0, len(cleaned), block_size))

def validate_alphabet(text: str, alphabet: Optional[str] = None) -> bool:
    """
    Check if text contains only characters from specified alphabet
    If alphabet is None, checks for standard English alphabet
    """
    if alphabet is None:
        alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    
    text = text.upper()
    return all(c in alphabet for c in text if c.isalpha())