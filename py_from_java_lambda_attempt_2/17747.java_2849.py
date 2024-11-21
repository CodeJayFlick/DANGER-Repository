Here is the translation of the Java code into Python:

```Python
import heapq
from unittest import TestCase
import os
import random

class CompactionTaskComparatorTest(TestCase):
    def setUp(self):
        self.logger = LoggerFactory.getLogger(CompactionTaskComparatorTest)
        self.task_num = AtomicInteger(0)

    @staticmethod
    def get_logger():
        return LoggerFactory.getLogger(CompactionTaskComparatorTest)

    def test_file_num_compare(self):
        compaction_tasks = [AbstractCompactionTask() for _ in range(100)]
        resources = []
        for i in range(100):
            for j in range(i, 100):
                resource = FakedTsFileResource(os.path.join(str(i + j), str(i + j)), j)
                resources.append(resource)

        compaction_tasks[i] = InnerSpaceCompactionTask("fakeSg", 0, self.task_num, True, resources)
        task_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator())
        for i in range(len(compaction_tasks)):
            task_queue.add(compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, compaction_tasks[99 - i])

    def test_file_size_compare(self):
        compaction_tasks = [AbstractCompactionTask() for _ in range(100)]
        resources = []
        for i in range(100):
            for j in range(i + 1):
                resource = FakedTsFileResource(os.path.join(str(i + j), str(i + j)), j - i + 101)
                resources.append(resource)

        compaction_tasks[i] = InnerSpaceCompactionTask("fakeSg", 0, self.task_num, True, resources)
        task_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator())
        for i in range(len(compaction_tasks)):
            task_queue.add(compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, compaction_tasks[99 - i])

    def test_file_compact_count_compare(self):
        compaction_tasks = [AbstractCompactionTask() for _ in range(100)]
        resources = []
        for i in range(10):
            for j in range(i + 1):
                resource = FakedTsFileResource(os.path.join(str(i), str(j)), 0)
                resources.append(resource)

        compaction_tasks[i] = InnerSpaceCompactionTask("fakeSg", 0, self.task_num, True, resources)
        task_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator())
        for i in range(len(compaction_tasks)):
            task_queue.add(compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, compaction_tasks[99 - i])

    def test_priority_queue_size_limit(self):
        limit_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator(), maximum_size=50)
        compaction_tasks = [AbstractCompactionTask() for _ in range(100)]
        resources = []
        for i in range(len(compaction_tasks)):
            for j in range(i + 1):
                resource = FakedTsFileResource(os.path.join(str(i), str(j)), j - i + 101)
                resources.append(resource)

            compaction_tasks[i] = InnerSpaceCompactionTask("fakeSg", 0, self.task_num, True, resources)
            limit_queue.add(compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, compaction_tasks[99 - i])

    def test_file_version_compare(self):
        compaction_tasks = [AbstractCompactionTask() for _ in range(100)]
        resources = []
        for i in range(len(compaction_tasks)):
            for j in range(i + 1):
                resource = FakedTsFileResource(os.path.join(str(i), str(j)), j)
                resources.append(resource)

        compaction_tasks[i] = InnerSpaceCompactionTask("fakeSg", 0, self.task_num, True, resources)
        task_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator())
        for i in range(len(compaction_tasks)):
            task_queue.add(compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, compaction_tasks[99 - i])

    def test_comparation_of_different_task_type(self):
        inner_compaction_tasks = [AbstractCompactionTask() for _ in range(100)]
        cross_compaction_tasks = [AbstractCompactionTask() for _ in range(100)]

        resources = []
        for i in range(len(inner_compaction_tasks)):
            for j in range(i + 1):
                resource = FakedTsFileResource(os.path.join(str(i), str(j)), j)
                resources.append(resource)

            inner_compaction_tasks[i] = InnerSpaceCompactionTask("fakeSg", 0, self.task_num, True, resources)

        sequence_resources = []
        unsequence_resources = []

        for i in range(len(cross_compaction_tasks)):
            for j in range(i + 1):
                resource = FakedTsFileResource(os.path.join(str(i), str(j)), j)
                sequence_resources.append(resource)

            for k in range(i, len(cross_compaction_tasks)):
                resource = FakedTsFileResource(os.path.join(str(k), str(k)), k - i + 101)
                unsequence_resources.append(resource)

            cross_compaction_tasks[i] = CrossSpaceCompactionTask("fakeSg", 0, self.task_num, sequence_resources, unsequence_resources)

        task_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator())
        for i in range(len(inner_compaction_tasks)):
            task_queue.add(inner_compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, inner_compaction_tasks[99 - i])

    def test_comparation_of_cross_space_task(self):
        cross_compaction_tasks = [AbstractCompactionTask() for _ in range(200)]

        resources_sequence = []
        resources_unsequence = []

        for i in range(len(cross_compaction_tasks)):
            if i < 100:
                for j in range(i + 1):
                    resource = FakedTsFileResource(os.path.join(str(i), str(j)), j)
                    resources_sequence.append(resource)

                for k in range(100, len(cross_compaction_tasks)):
                    resource = FakedTsFileResource(os.path.join(str(k), str(k)), k - i + 101)
                    resources_unsequence.append(resource)

            else:
                for j in range(i):
                    resource = FakedTsFileResource(os.path.join(str(j), str(j)), j)
                    resources_sequence.append(resource)

                for k in range(100, len(cross_compaction_tasks)):
                    resource = FakedTsFileResource(os.path.join(str(k), str(k)), k - i + 101)
                    resources_unsequence.append(resource)

            cross_compaction_tasks[i] = CrossSpaceCompactionTask("fakeSg", 0, self.task_num, resources_sequence, resources_unsequence)

        task_queue = MinMaxPriorityQueue(ordered_by=CompactionTaskComparator())
        for i in range(len(cross_compaction_tasks)):
            task_queue.add(cross_compaction_tasks[i])

        current_task = None
        while not task_queue.empty():
            current_task = task_queue.poll()
            self.assertEqual(current_task, cross_compaction_tasks[199 - i])


class InnerSpaceCompactionTask(AbstractInnerSpaceCompactionTask):
    def __init__(self, storage_group_name, time_partition, task_num, sequence, resources):
        super().__init__(storage_group_name, time_partition, task_num, sequence, resources)

    @staticmethod
    def do_compaction():
        pass

    @staticmethod
    def equals_other_task(other):
        return False

    @staticmethod
    def check_valid_and_set_merging():
        return True


class CrossSpaceCompactionTask(AbstractCrossSpaceCompactionTask):
    def __init__(self, full_storage_group_name, time_partition, task_num, sequence_files, unsequence_files):
        super().__init__(full_storage_group_name, time_partition, task_num, sequence_files, unsequence_files)

    @staticmethod
    def do_compaction():
        pass

    @staticmethod
    def equals_other_task(other):
        return False

    @staticmethod
    def check_valid_and_set_merging():
        return True


class FakedTsFileResource(TsFileResource):
    def __init__(self, tsfile, tsfile_size):
        super().__init__(tsfile)
        self.tsfile_size = tsfile_size

    def get_ts_file_size(self):
        return self.tsfile_size
```

Please note that the above Python code is a direct translation of your Java code.