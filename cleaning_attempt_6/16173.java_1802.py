import unittest
from ai_djl_examples_inference import LightFaceDetection
try:
    from ai_djl_translate import TranslateException
except ImportError as e:
    print(f"Error: {e}")
try:
    from ai_djl_engine import Engine, ModelException
except ImportError as e:
    print(f"Error: {e}")

class TestLightFaceDetection(unittest.TestCase):

    def test_light_face_detection(self):
        if not isinstance(Engine.getInstance(), str) or "PyTorch" != Engine.getInstance():
            self.skipTest("Only works for PyTorch engine.")

        nightly = True  # Assuming this is a boolean variable
        result = LightFaceDetection.predict()

        objects = ["Face"]
        for obj in result.items:
            self.assertTrue(obj.getClassName() in objects)
            self.assertGreaterEqual(obj.getProbability(), 0.6)

if __name__ == '__main__':
    unittest.main()
