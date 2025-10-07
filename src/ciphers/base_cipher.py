class BaseCipher:
    def encode(self, plaintext):
        """Encode the given plaintext. This method should be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement this method.")

    def decode(self, ciphertext):
        """Decode the given ciphertext. This method should be overridden by subclasses."""
        raise NotImplementedError("Subclasses must implement this method.")