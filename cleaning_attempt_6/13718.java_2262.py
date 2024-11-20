# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class ModemVisitor:
    """Modem visitor interface does not contain any visit methods so that it 
       does not depend on the visited hierarchy. Each derivative's visit method is declared in its own visitor interface"""
    
    pass
