def validate_input(input_data):
    # Function to validate the input data for cipher operations
    if not isinstance(input_data, str):
        raise ValueError("Input data must be a string.")
    if not input_data:
        raise ValueError("Input data cannot be empty.")

def transform_text(text):
    # Function to perform common transformations on text
    return text.strip().lower()  # Example transformation: strip whitespace and convert to lowercase

# Additional utility functions can be added here as needed.