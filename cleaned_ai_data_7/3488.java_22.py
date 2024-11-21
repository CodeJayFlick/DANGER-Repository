import hashlib

class SHA384DigestChecksumAlgorithm:
    def __init__(self):
        super().__init__("SHA-384")

# Note: The 'super' function in Python doesn't work exactly like it does in Java.
# It's not necessary to use it here, but I kept it for consistency with the original code.

def main():
    algorithm = SHA384DigestChecksumAlgorithm()

if __name__ == "__main__":
    main()
