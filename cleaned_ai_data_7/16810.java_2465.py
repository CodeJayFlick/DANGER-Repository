import os
from typing import List

class RowTSRecordOutputFormatTest:
    def test_write_data(self):
        output_dir_path = os.path.join(temporary_directory, "test_output")
        os.makedirs(output_dir_path)
        
        from tsrecordoutputformat import TSRecordOutputFormat
        output_format = prepare_ts_record_output_format(output_dir_path)

        try:
            output_format.configure(configuration())
            output_format.open(0, 2)
            
            data: List[Row] = prepare_data()
            for row in data:
                output_format.write_record(row)
                
        finally:
            output_format.close()

        actual = read_ts_file(os.path.join(output_dir_path, "1.tsfile"), paths)
        expected = [
            "1,1.2,20,null,2.3,11,19",
            "2,null,20,50,25.4,10,21",
            "3,1.4,21,null,null,null,null",
            "4,1.2,20,51,null,null,null",
            "6,7.2,10,11,null,null,null",
            "7,6.2,20,21,null,null,null",
            "8,9.2,30,31,null,null,null"
        ]
        
        self.assertEqual(actual, expected)

    def test_getter(self):
        output_file_path = os.path.join(temporary_directory, "test.tsfile")
        from tsrecordoutputformat import TSRecordOutputFormat
        output_format = prepare_ts_record_output_format(output_file_path)
        
        self.assertEqual(row_ts_record_converter, output_format.get_converter())
        self.assertEqual(schema, output_format.get_schema())
        self.assertEqual(config, output_format.get_config().get())

if __name__ == "__main__":
    test_write_data()
    test_getter()

