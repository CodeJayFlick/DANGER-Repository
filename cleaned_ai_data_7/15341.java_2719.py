import unittest
from io import IOException


class WalletUtilsTest(unittest.TestCase):

    def test_restore_wallet_from_protobuf_or_base58(self):
        try:
            from wallet_utils import restore_wallet_from_protobuf
            stream = self.getClass().getResourceAsStream("backup-protobuf-testnet")
            TestNet3Params.get()
            restore_wallet_from_protobuf(stream, TestNet3Params.get())
        except Exception as e:
            raise

    def test_restore_wallet_from_protobuf_wrong_network(self):
        try:
            from wallet_utils import restore_wallet_from_protobuf
            stream = self.getClass().getResourceAsStream("backup-protobuf-testnet")
            MainNetParams.get()
            restore_wallet_from_protobuf(stream, MainNetParams.get())
        except IOException as e:
            pass


if __name__ == '__main__':
    unittest.main()
