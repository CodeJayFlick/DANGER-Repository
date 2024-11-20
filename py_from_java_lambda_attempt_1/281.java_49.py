Here is the translation of the given Java code into equivalent Python:

```Python
from typing import Any, Dict, List, Tuple

class RecorderComposedMemory:
    BLOCK_SIZE = 4096
    BLOCK_MASK = -1 << 12

    def __init__(self, memory: 'AbstractRecorderMemory'):
        self.chain = memory if isinstance(memory, RecorderComposedMemory) else None

    @property
    def by_min(self):
        return self._by_min

    @by_min.setter
    def by_min(self, value: Dict[Tuple[int], Tuple[Any]]):
        self._by_min = TreeMap(value)

    @property
    def by_region(self):
        return self._by_region

    @by_region.setter
    def by_region(self, value: Dict[TargetMemoryRegion, TargetMemory]):
        self._by_region = dict(value)

    def get_accessible_memory(
            self,
            predicate: Predicate[TargetMemory],
            mem_mapper: DebuggerMemoryMapper) -> AddressSet:
        with self.accessibility_by_memory as lock:
            accessible_set = set()
            for entry in self.by_region.items():
                target_memory, memory = entry
                if not predicate.test(memory):
                    continue

                all_required_access = self.accessibility_by_memory.get_completed_map().get(target_memory)
                if all_required_access is None or not all_required_access.all_accessibility:
                    continue

                accessible_set.add(mem_mapper.target_to_trace(entry[0].range))
            return accessible_set

    def fetch_mem_accessibility(self, target_memory: TargetMemory) -> CompletableFuture[AllRequiredAccess]:
        return DebugModelConventions.track_accessibility(target_memory).then_apply(lambda acc: (acc.add_change_listener(get_mem_acc_listeners().fire), acc))

    @property
    def mem_acc_listeners(self):
        if not hasattr(self, '_mem_acc_listeners'):
            self._mem_acc_listeners = ListenerSet(TriConsumer)
        return self._mem_acc_listeners

    def get_memory(self, address: Address, length: int) -> TargetMemory:
        floor_entry = self.by_min.floor_entry(address)
        if floor_entry is None:
            raise ValueError(f"address {address} is not in any known region")

        max_address = address.add_no_wrap(length - 1)
        try:
            pass
        except AddressOverflowException as e:
            raise ValueError("read extends beyond the address space") from e

        if not floor_entry[0].range.contains(max_address):
            raise ValueError("read extends beyond a single region")

        return self.by_region.get(floor_entry[0])

    def add_region(self, target_memory_region: TargetMemoryRegion, memory: TargetMemory) -> None:
        with self.accessibility_by_memory as lock:
            old = self.by_region.put(target_memory_region, memory)
            assert old is None
            self.by_min.put(target_memory_region.range.min_address(), target_memory_region)

    def remove_region(self, invalid: Any) -> bool:
        if not isinstance(invalid, TargetMemoryRegion):
            return False

        with self.accessibility_by_memory as lock:
            region = (TargetMemoryRegion)(invalid)
            old = self.by_region.pop(region)
            assert old is not None
            self.by_min.remove(region.range.min_address())

    def find_chained_floor(self, address: Address) -> Tuple[Address, TargetMemoryRegion]:
        with self.accessibility_by_memory as lock:
            my_floor_entry = self.by_min.floor_entry(address)
            by_chain_entry = self.chain.find_chained_floor(address) if self.chain else None

            if by_chain_entry is None:
                return my_floor_entry
            elif my_floor_entry is None:
                return by_chain_entry
            else:
                c = address_to_int(my_floor_entry[0]) - address_to_int(by_chain_entry[0])
                if c < 0:
                    return by_chain_entry
                return my_floor_entry

    def align(self, address: Address, length: int) -> Tuple[int, int]:
        space = address.get_address_space()
        offset = address.get_offset()
        start = space.get_address(offset & self.BLOCK_MASK)
        end = space.get_address(((offset + length - 1) & self.BLOCK_MASK) + self.BLOCK_SIZE - 1)

        return (address_to_int(start), address_to_int(end))

    def align_with_limit(self, address: Address, length: int, limit: TargetMemoryRegion):
        start, end = self.align(address, length)
        return ((start, min(int(limit.range.max_address), end)),)

    @property
    def accessibility_by_memory(self) -> AsyncLazyMap[TargetMemory, AllRequiredAccess]:
        if not hasattr(self, '_accessibility_by_memory'):
            self._accessibility_by_memory = AsyncLazyMap({}, lambda mem: self.fetch_mem_accessibility(mem))
        return self._accessibility_by_memory

class AddressSet:
    def __init__(self):
        pass
```

Note that Python does not have direct equivalents for Java's `synchronized` keyword or its `CompletableFuture`. The equivalent of these in Python would be using locks and threads, respectively.