Here is the equivalent Python code:

```Python
class Img2Constants:
    """IMG2 constants"""
    
    IMG2_SIGNATURE = "Img2"
    IMG2_SIGNATURE_BYTES = bytes("Img2", 'utf-8')
    
    IMG2_LENGTH = 0x400
    
    IMAGE_TYPES = {
        "logo": "apple logo",
        "batC": "batterycharging",
        "batl": "battery low 0",
        "batL": "battery low 1",
        "dtre": "Device Tree (m68ap)",
        "ibot": "iBoot (m68a9, RELEASE)",
        "llbz": "LLB (m68ap, RELEASE)",
        "nsvr": "needs service",
        "recm": "recovery mode"
    }
```

Note that Python does not have a direct equivalent to Java's `public final static` keywords. In Python, we can achieve similar functionality using classes and dictionaries.