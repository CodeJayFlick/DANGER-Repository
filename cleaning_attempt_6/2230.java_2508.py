import asyncio
from collections import defaultdict, OrderedDict

class TargetDataTypeConverter:
    def __init__(self):
        self.dtm = None
        self.types = defaultdict(dict)

    class ConvertedMember:
        def __init__(self, member: 'TargetDataTypeMember', type: 'DataType'):
            self.member = member
            self.type = type

    async def do_start(self) -> None:
        pass

    class TwoPhased(T):
        def __init__(self, one: asyncio.Future[T], two: asyncio.Future[None]):
            self.one = one
            self.two = two
            self.deps = set()
            self.started = False

        async def start(self) -> None:
            if not self.started:
                self.started = True
                await self.do_start()

        async def chain_exc(self, chain: 'TwoPhased') -> None:
            await asyncio.wait([chain.one, chain.two])

    class TwoPhasedComposite(TwoPhased[T]):
        def __init__(self, type: T, t_named: 'TargetNamedDataType'):
            self.type = type
            self.t_named = t_named

        async def do_start(self) -> None:
            await asyncio.wait([self.one, self.two])

    class ConvertedMember(T):
        pass

    async def convert_target_data_type(self, target_data_type: 'TargetDataType') -> asyncio.Future[None]:
        return (await self.convert_two_phased(target_data_type)).dep_twos()

    async def convert_two_phased(self, target_data_type: 'TargetDataType') -> TwoPhased[T]:
        if not self.types[target_data_type].get():
            self.types[target_data_type][target_data_type] = await self.do_convert_target_data_type(target_data_type)
        return self.types[target_data_type][target_data_type]

    async def do_convert_target_named_data_type(self, t_named: 'TargetNamedDataType') -> TwoPhased[EnumDataType]:
        # ...
        pass

    async def convert_target_array_data_type(self, t_array: 'TargetArrayDataType') -> asyncio.Future[T]:
        return (await self.convert_two_phased(t_array.get_element_type())).then(lambda c_elem: ArrayDataType(c_elem, t_array.get_element_count(), c_elem.get_length()))

    # ...
