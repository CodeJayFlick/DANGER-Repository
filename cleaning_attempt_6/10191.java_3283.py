class FNV1a64MessageDigestFactory:
    def create_digest(self):
        from . import fnv1a64_message_digest
        return fnv1a64_message_digest.FNV1a64MessageDigest()
