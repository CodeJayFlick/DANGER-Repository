import asyncio
from typing import List, Tuple

class DataIterable:
    def __init__(self,
                 dataset: 'RandomAccessDataset',
                 manager: 'NDManager',
                 sampler: 'Sampler',
                 data_batchifier: 'Batchifier',
                 label_batchifier: 'Batchifier',
                 pipeline: 'Pipeline',
                 target_pipeline: 'Pipeline',
                 executor: asyncio.Scheduler | None = None,
                 pre_fetch_number: int = 0,
                 device: 'Device' | None = None):
        self.dataset = dataset
        self.manager = manager.new_sub_manager()
        self.data_batchifier = data_batchifier
        self.label_batchifier = label_batchifier
        self.pipeline = pipeline
        self.target_pipeline = target_pipeline
        self.executor = executor
        self.device = device

    def __iter__(self):
        return self

    async def next(self) -> Tuple[List[int], List[NDList]]:
        if not hasattr(self, 'sample'):
            raise StopIteration
        
        indices = await self.sample.next()
        
        try:
            batch_data, batch_labels = await fetch(indices)
            return indices, (batch_data, batch_labels)
        except Exception as e:
            print(f"Error: {e}")
            raise

    async def pre_fetch(self):
        if not hasattr(self, 'sample'):
            return
        
        indices = await self.sample.next()
        
        task = asyncio.create_task(fetch(indices))
        queue.put_nowait(task)

class PreFetchCallable:
    def __init__(self, indices: List[int]):
        self.indices = indices

    async def call(self) -> Tuple[List[NDList], List[NDList]]:
        return await fetch(self.indices)
