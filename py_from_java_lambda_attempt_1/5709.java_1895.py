Here is a translation of the Java code into equivalent Python:

```Python
class GhidraDataFlavorHandlerService:
    def __init__(self):
        # Note: the order of the file drop flavors/handlers is intentional.
        # We wish to process objects first which we know to be transfered from within the current JVM. 
        # After that, then process objects given to us from the OS or another JVM.

        local_node_handler = LocalTreeNodeHandler()
        DataTreeDragNDropHandler.add_active_data_flavor_handler(
            DataTreeDragNDropHandler.local_domain_file_tree_flavor,
            local_node_handler
        )

        data_tree_drag_ndrop_handler.add_active_data_flavor_handler(
            VersionInfoTransferable.local_version_info_flavor,
            LocalVersionInfoHandler()
        )
        
        data_tree_drag_ndrop_handler.add_active_data_flavor_handler(DataFlavor.java_file_list_flavor, 
            JavaFileListHandler())

        linux_file_url_flavor = DataFlavor("application/x-java-serialized-object;class=java.lang.String", "String file URL")
        data_tree_drag_ndrop_handler.add_active_data_flavor_handler(linux_file_url_flavor,
            LinuxFileUrlHandler())
```

Note that this is a direct translation of the Java code into Python, without considering any potential differences in how these concepts are implemented or used in each language.