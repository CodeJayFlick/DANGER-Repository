Here is the translation of the given Java code into Python:

```Python
import unittest

class Utils:
    max_error = 0.0001
    
    def __init__(self):
        pass

    @staticmethod
    def is_two_objects_not_null(obj_a, obj_b, name):
        if (obj_a is None) and (obj_b is None):
            return False
        
        if ((obj_a is None) ^ (obj_b is None)):
            raise AssertionError(f"One of {name} is null")
        
        return True

    @staticmethod
    def are_file_metadata_equal(metadata1, metadata2):
        if not Utils.is_two_objects_not_null(metadata1, metadata2, "File MetaData"):
            return False
        
        if not Utils.is_two_objects_not_null(
                metadata1.get_metadata_index(), 
                metadata2.get_metadata_index(), 
                "Metadata Index"
        ):
            return False
        
        meta_data_index_1 = metadata1.get_metadata_index()
        meta_data_index_2 = metadata2.get_metadata_index()
        
        return len(meta_data_index_1.children) == len(meta_data_index_2.children)

    @staticmethod
    def are_page_headers_equal(header1, header2):
        if not Utils.is_two_objects_not_null(header1, header2, "PageHeader"):
            return
        
        assert header1.uncompressed_size == header2.uncompressed_size
        assert header1.compressed_size == header2.compressed_size
        assert header1.num_of_values == header2.num_of_values
        assert header1.end_time == header2.end_time
        assert header1.start_time == header2.start_time
        
        if not Utils.is_two_objects_not_null(
                header1.get_statistics(), 
                header2.get_statistics(), 
                "statistics"
        ):
            return
        
        Utils.are_statistics_equal(header1.get_statistics(), header2.get_statistics())

    @staticmethod
    def are_statistics_equal(statistics_1, statistics_2):
        if (statistics_1 is None) or (statistics_2 is None):
            raise AssertionError("One of the statistics is null")
        
        if not statistics_1.is_empty() and not statistics_2.is_empty():
            assert statistics_1.min_value == statistics_2.min_value
            assert statistics_1.max_value == statistics_2.max_value
            assert statistics_1.first_value == statistics_2.first_value
            
            if isinstance(statistics_1, (int, float)):
                assert abs(statistics_1.sum_long_value - statistics_2.sum_long_value) < max_error
            else:
                assert statistics_1.sum_double_value == statistics_2.sum_double_value
        
        return True

if __name__ == "__main__":
    # You can test the functions here.
    pass
```

Please note that Python does not have direct equivalent of Java's `@staticmethod` or `^` operator. Also, there is no built-in function to check if two objects are equal in Python (like `assertEquals()` in Java).