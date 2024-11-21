import unittest
from ai_djl_translate import PoseEstimation

class TestPoseEstimation(unittest.TestCase):
    def test_pose_estimation(self):
        try:
            result = PoseEstimation.predict()
            self.assertTrue(result[0].confidence > 0.6)
        except (ModelException, TranslateException, IOException) as e:
            raise
