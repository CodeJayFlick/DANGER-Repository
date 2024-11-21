# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class MessagingDatabase:
    def __init__(self):
        self.data = {}

    def add(self, r: dict) -> dict:
        return {**self.data, **{r['reqId']: r}}

    def get(self, requestId: str) -> dict or None:
        return self.data.get(requestId)
