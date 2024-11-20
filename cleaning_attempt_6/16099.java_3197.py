import unittest

class TrtEngineTest(unittest.TestCase):
    def test_get_version(self):
        try:
            import djl_engine as engine
            version = engine.get_version("TensorRT")
        except Exception as e:
            self.skipTest(f"Your OS configuration doesn't support TensorRT: {e}")
        self.assertEqual(version, "8.0.1")

if __name__ == '__main__':
    unittest.main()
