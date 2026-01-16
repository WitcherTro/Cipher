# Cipher Project

A Python-based collection of classical and modern encryption algorithms and cryptanalysis tools.

## Features

### Implemented Ciphers
The project includes implementations for the following ciphers:
- **Base Cipher**: Abstract base class for all cipher implementations.
- **Caesar Cipher**: Simple substitution cipher.
- **Hill Cipher**: Polygraphic substitution cipher based on linear algebra.
- **Vigenère Cipher**: Polyalphabetic substitution cipher.
- **Stream Cipher**: Byte-oriented stream cipher (RC4-like).
- **RSA**: Public-key cryptosystem.

### Tools
- **Frequency Analysis**: Tools for analyzing character frequency in texts (English/Slovak).
- **Text Utilities**: Helper functions for text processing.

## Project Structure

```
Cipher/
├── src/
│   ├── ciphers/           # Core cipher implementations
│   ├── frequency_files/   # Language statistics for analysis
│   ├── tools/             # Analysis and utility scripts
│   └── main.py            # Main application logic
├── tests/                 # Unit tests
├── requirements.txt       # Project dependencies
└── run.py                 # Application entry point
```

## Getting Started

### Prerequisites
- Python 3.x

### Installation

1. Clone the repository (if applicable)
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Usage

Run the application using the entry script:

```bash
python run.py
```
