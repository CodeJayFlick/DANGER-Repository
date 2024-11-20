Here's the translation of the given Java code into Python:

```Python
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ModemVisitor:
    """Modem visitor interface does not contain any visit methods so that it 
       does not depend on the visited hierarchy. Each derivative's visit method is declared in its own visitor interface"""
    
    pass
```

Please note that Python doesn't have direct equivalent of Java interfaces, but we can achieve similar functionality using abstract classes or protocols (in Python 3.x). In this case, I've used a simple class with no methods to mimic the behavior of an interface.