class KBagTag:
    MAGIC = "KBAG"
    AES_128 = 0x080
    AES_192 = 0x0c0
    AES_256 = 0x100

    def __init__(self, reader):
        self.iv_key_crypt_state = reader.read_int()
        self.aes_type = reader.read_int()
        self.enc_iv = reader.read_bytes(16)

        if self.aes_type == KBagTag.AES_128:
            self.enc_key = reader.read_bytes(16)
        elif self.aes_type == KBagTag.AES_192:
            self.enc_key = reader.read_bytes(24)
        elif self.aes_type == KBagTag.AES_256:
            self.enc_key = reader.read_bytes(32)
        else:
            raise RuntimeError(f"unrecognized AES size: {self.aes_type}")

    def get_iv_key_crypt_state(self):
        return self.iv_key_crypt_state

    def get_aes_type(self):
        return self.aes_type

    def get_encryption_iv(self):
        return self.enc_iv

    def get_encryption_key(self):
        return self.enc_key
