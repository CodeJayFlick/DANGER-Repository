import os
from typing import List

class ExternalSortJob:
    def __init__(self, part_list: List):
        self.part_list = part_list

    def execute_for_i_point_reader(self) -> List:
        readers = []
        for part in self.part_list:
            readers.append(part.execute_for_i_point_reader())
        return readers


# Example usage
part_list = [...]  # replace with your list of ExternalSortJobPart objects
job = ExternalSortJob(part_list)
readers = job.execute_for_i_point_reader()
