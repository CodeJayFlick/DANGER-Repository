Here is the translation of the Java code to Python:
```
# MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import inject

class LotteryTestingModule:
    def configure(self):
        self.bind(LotteryTicketRepository).to(InMemoryTicketRepository)
        self.bind(LotteryEventLog).to(StdOutEventLog)
        self.bind(WireTransfers).to(InMemoryBank)

LotteryTicketRepository = object
InMemoryTicketRepository = object

LotteryEventLog = object
StdOutEventLog = object

WireTransfers = object
InMemoryBank = object
```
Note that I've kept the same variable names as in the original Java code, but replaced `public class` with just `class`, since Python doesn't have a concept of public or private classes. Also, I didn't include any imports for modules like Guice, since we're not using them here (we're simply defining our own module).