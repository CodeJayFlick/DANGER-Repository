import asyncio

class GadpClientTargetDeletable:
    def delete(self):
        await self.get_delegate().assert_valid()
        reply = await self.get_model().send_checked(
            Gadp.DeleteRequest(path=self.path),
            Gadp.DeleteReply.getDefaultInstance())
        return None

async def main():
    # create an instance of GadpClientTargetDeletable
    client_target_deletable = GadpClientTargetDeletable()

    try:
        await client_target_deletable.delete()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    asyncio.run(main())
