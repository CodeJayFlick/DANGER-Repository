import asyncio

class GadpClientTargetDetachable:
    def __init__(self):
        pass

    async def detach(self) -> None:
        await self.get_delegate().assert_valid()
        reply = await self.get_model().send_checked(
            Gadp.DetachRequest.newBuilder().set_path(GadpValueUtils.make_path(self.get_path())).build(),
            Gadp.DetachReply.getDefaultInstance())
