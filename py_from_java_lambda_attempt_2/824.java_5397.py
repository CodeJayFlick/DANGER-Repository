Here is a translation of the Java code into equivalent Python code:

```Python
import asyncio

class DbgModelTargetSessionContainer:
    def __init__(self, root):
        self.root = root
        self.model = None
        self.manager = None
        self.sessionsById = {}

    async def session_added(self, sess, cause):
        if isinstance(sess, DbgSession):
            await asyncio.create_task(self.change_elements(None, [sess], {}, "Added"))

    async def session_removed(self, sessionId, cause):
        #await asyncio.create_task(sessionsById.pop(sessionId))
        await self.change_elements([DbgModelTargetSession.index_session(sessionId)], [], {}, "Removed")

    async def get_target_session(self, sess):
        if isinstance(sess, DbgSession) and hasattr(self.model, 'getModelObject'):
            model_object = getattr(self.model, 'getModelObject')(sess)
            return model_object
        else:
            return DbgModelTargetSession(self, sess)

    async def request_elements(self, refresh=False):
        #if self.manager.check_access_prohibited():
        #    return asyncio.create_task(asyncio.sleep(0), elementsView=self.elements_view)
        if hasattr(self.manager, 'list_sessions'):
            sessions = await self.manager.list_sessions()
            for by_iid in sessions:
                session_list = [self.get_target_session(sess) for sess in by_iid.values()]
                await self.change_elements(None, session_list, {}, "Refreshed")
            return asyncio.create_task(asyncio.sleep(0), elementsView=self.elements_view)
        else:
            return asyncio.create_task(asyncio.sleep(0))

    async def change_elements(self, *args):
        pass

class DbgModelTargetSession:
    @classmethod
    def index_session(cls, sessionId):
        # todo: implement this method
        pass

# Note that the above Python code is a translation of Java code and may not be directly executable.
```

This translation maintains the same structure as the original Java code. However, note that some parts like `@TargetObjectSchemaInfo`, `DbgModelTargetSessionImpl` are missing in this Python version because they don't have direct equivalents in Python.