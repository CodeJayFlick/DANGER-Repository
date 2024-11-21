import unittest
from typing import List

class MaxSeriesMergeFileSelectorTest(unittest.TestCase):

    def test_full_selection(self):
        seq_resources = [1, 2, 3]
        unseq_resources = [4, 5, 6]

        resource = CrossSpaceMergeResource(seq_resources, unseq_resources)
        merge_file_selector = MaxSeriesMergeFileSelector(resource, float('inf'))
        result = merge_file_selector.select()
        seq_selected = result[0]
        unseq_selected = result[1]
        self.assertEqual(seq_resources, seq_selected)
        self.assertEqual(unseq_resources, unseq_selected)
        self.assertEqual(MaxSeriesMergeFileSelector.MAX_SERIES_NUM, merge_file_selector.concurrent_merge_num)

    def test_non_selection(self):
        seq_resources = [1, 2, 3]
        unseq_resources = [4, 5, 6]

        resource = CrossSpaceMergeResource(seq_resources, unseq_resources)
        merge_file_selector = MaxSeriesMergeFileSelector(resource, 1)
        result = merge_file_selector.select()
        self.assertEqual([], result)

    def test_restricted_selection(self):
        seq_resources = list(range(8))
        unseq_resources = list(range(16))

        resource = CrossSpaceMergeResource(seq_resources[:4], unseq_resources[:4])
        merge_file_selector = MaxSeriesMergeFileSelector(resource, 400000)
        result = merge_file_selector.select()
        seq_selected = result[0]
        unseq_selected = result[1]
        self.assertEqual(seq_resources[:4], seq_selected)
        self.assertEqual(unseq_resources[:4], unseq_selected)

    def test_restricted_selection2(self):
        seq_resources = list(range(8))
        unseq_resources = list(range(16))

        resource = CrossSpaceMergeResource(seq_resources[:2], unseq_resources[:2])
        merge_file_selector = MaxSeriesMergeFileSelector(resource, 100000)
        result = merge_file_selector.select()
        seq_selected = result[0]
        unseq_selected = result[1]
        self.assertEqual(seq_resources[:2], seq_selected)
        self.assertEqual(unseq_resources[:2], unseq_selected)

class CrossSpaceMergeResource:
    def __init__(self, seq_resources: List[int], unseq_resources: List[int]):
        pass

class MaxSeriesMergeFileSelector:
    MAX_SERIES_NUM = 1000
    def __init__(self, resource: 'CrossSpaceMergeResource', concurrent_merge_num):
        self.resource = resource
        self.concurrent_merge_num = concurrent_merge_num

    def select(self) -> (List[int], List[int]):
        return [], []

if __name__ == '__main__':
    unittest.main()
