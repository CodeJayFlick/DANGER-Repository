class TsFileProcessorInfo:
    def __init__(self, storage_group_info):
        self.storage_group_info = storage_group_info
        self.mem_cost = 0

    def add_tsp_mem_cost(self, cost):
        self.mem_cost += cost
        self.storage_group_info.add_storage_group_mem_cost(cost)

    def release_tsp_mem_cost(self, cost):
        self.storage_group_info.release_storage_group_mem_cost(cost)
        self.mem_cost -= cost

    def clear(self):
        self.storage_group_info.release_storage_group_mem_cost(self.mem_cost)
        self.mem_cost = 0
