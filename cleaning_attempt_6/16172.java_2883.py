import unittest
from ai_djl_translate import DetectedObjects, Classifications

class InstanceSegmentationTest(unittest.TestCase):

    def test_instance_segmentation(self):
        try:
            result = InstanceSegmentation.predict()
            best = result.best()
            self.assertEqual(best.class_name, "bicycle")
            self.assertTrue(abs(best.probability - 0.9) < 1e-6)
        except (ModelException, TranslateException, IOException) as e:
            raise

if __name__ == '__main__':
    unittest.main()
