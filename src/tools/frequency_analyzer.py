from collections import Counter
from typing import Dict, Optional
import json
import os

class FrequencyAnalyzer:
    def __init__(self, language: str = "english"):
        """Initialize analyzer with specified language"""
        self.frequencies = {}
        self.language = language.lower()
        self._load_default_frequencies()
        self.set_language(language)

    def _load_default_frequencies(self) -> None:
        """Load frequencies from frequency_files directory"""
        frequency_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'frequency_files')
        
        for filename in os.listdir(frequency_dir):
            if filename.endswith('.json'):
                language = filename.split('.')[0].lower()
                filepath = os.path.join(frequency_dir, filename)
                with open(filepath, 'r') as file:
                    self.frequencies[language] = json.load(file)

    def set_language(self, language: str) -> None:
        """Change the analysis language"""
        language = language.lower()
        if language not in self.frequencies:
            raise ValueError(f"Unsupported language: {language}. Available languages: {self.get_supported_languages()}")
        self.language = language

    def analyze_text(self, text: str) -> Dict[str, float]:
        """Analyze letter frequencies in the given text"""
        text = ''.join(c.upper() for c in text if c.isalpha())
        if not text:
            return {}

        total_chars = len(text)
        char_counts = Counter(text)

        return {
            char: (count / total_chars) * 100
            for char, count in char_counts.items()
        }

    def compare_to_language(self, frequencies: Dict[str, float]) -> float:
        """Compare given frequencies to current language pattern"""
        difference = 0.0
        current_freq = self.frequencies[self.language]
        for char, freq in frequencies.items():
            if char in current_freq:
                difference += abs(freq - current_freq[char])
        return difference

    def get_supported_languages(self) -> list:
        """Return list of supported languages"""
        return list(self.frequencies.keys())