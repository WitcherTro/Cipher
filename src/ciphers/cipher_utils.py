def clean_text(text: str) -> str:
    """Remove spaces and convert to uppercase"""
    return text.replace(" ", "").upper()

def is_valid_input(text: str) -> bool:
    """Check if input contains only letters"""
    return text.replace(" ", "").isalpha()