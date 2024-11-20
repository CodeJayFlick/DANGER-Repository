Here is the equivalent Python code:

```Python
class FSType:
    HDFS = 'HDFS'
    LOCAL_FS = 'LOCAL_FS'

f_stype = TSFileDescriptor().get_config()['ts_file_storage_fs']

fs_factory = None
file_input_factory = None
file_output_factory = None

def __init__():
    global fs_factory, file_input_factory, file_output_factory
    
    if f_stype == FSType.HDFS:
        from hdfs import InsecureClient as HDFSFactory
        from hdfs.ext.hdfs.inputfactory import HDFSInputFactory as HDFSInputFactory
        from hdfs.ext.hdfs.outputfactory import HDFSOutputFactory as HDFSOutputFactory
        
        fs_factory = HDFSFactory()
        file_input_factory = HDFSInputFactory()
        file_output_factory = HDFSOutputFactory()
    else:
        from localfs import LocalFSFactory as LocalFSFactory
        from localfs.inputfactory import LocalFSInputFactory as LocalFSInputFactory
        from localfs.outputfactory import LocalFSOutputFactory as LocalFSOutputFactory
        
        fs_factory = LocalFSFactory()
        file_input_factory = LocalFSInputFactory()
        file_output_factory = LocalFSOutputFactory()

__init__()

def get_fs_factory():
    return fs_factory

def get_file_input_factory():
    return file_input_factory

def get_file_output_factory():
    return file_output_factory
```

Please note that this Python code is not a direct translation of the Java code. It's more like an equivalent implementation in Python, as there are some differences between the two languages.