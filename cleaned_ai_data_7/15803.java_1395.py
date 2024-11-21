import unittest

class TfhubRepositoryTest(unittest.TestCase):
    def test_resource(self):
        repo = Repository("tfhub", "https://tfhub.dev/tensorflow/faster_rcnn/inception_resnet_v2_640x640/1/")
        self.assertEqual(len(repo.get_resources()), 1)

if __name__ == '__main__':
    unittest.main()
