class AsyncConfigFieldCodec:
    class GenericAsyncConfigFieldCodec(T):
        def __init__(self, codec: ConfigFieldCodec[T]):
            self.codec = codec

        @staticmethod
        async def read(state: SaveState, name: str, current: AsyncReference[T]) -> AsyncReference[T]:
            current.set(codec.read(state, name, current.get()), None)
            return current

        @staticmethod
        async def write(state: SaveState, name: str, value: AsyncReference[T]):
            codec.write(state, name, value.get())

    class BooleanAsyncConfigFieldCodec(GenericAsyncConfigFieldCodec[bool]):
        def __init__(self):
            super().__init__(BooleanConfigFieldCodec.INSTANCE)

# TODO: Other types as needed
