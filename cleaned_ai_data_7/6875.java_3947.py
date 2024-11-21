import concurrent.futures as futures
from typing import List, Any, Callable, Collection

class ParallelDecompiler:
    THREAD_POOL_NAME = "Parallel Decompiler"

    def __init__(self):
        pass  # only use statically

    @staticmethod
    def decompile_functions(callback: Callable[[Any], Any], program, addresses, monitor) -> List[Any]:
        function_count = program.get_function_manager().get_function_count()
        listing = program.get_listing()
        iterator = listing.get_functions(addresses, True)

        results = ParallelDecompiler.do_decompile_functions(callback, iterator, function_count, monitor)
        return results

    @staticmethod
    def do_decompile_functions(callback: Callable[[Any], Any], functions: Collection[Any], count: int, monitor) -> List[Any]:
        queue = futures.ThreadPoolExecutor(max_workers=count).submit(lambda x: [callback(x) for _ in range(count)]).result()
        
        return list(queue)

class ChunkingParallelDecompiler:
    def __init__(self, callback: Callable[[Any], Any], monitor):
        self.callback = callback
        self.monitor = monitor

    @staticmethod
    def create_chunking_parallel_decompiler(callback: Callable[[Any], Any], monitor) -> 'ChunkingParallelDecompiler':
        return ChunkingParallelDecompiler(callback, monitor)
