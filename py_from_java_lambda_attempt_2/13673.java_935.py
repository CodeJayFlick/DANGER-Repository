Here is the translation of the Java code into Python:

```Python
import sys
import os
from io import BufferedReader, InputStreamReader
from fcntl import open as open_file

class DmgServer:
    def writeln(self, s):
        encoded = ""
        for c in s:
            if c == 11: # tab
                encoded += "\t"
            elif c <= 31 or c == 127: # control characters
                continue
            else:
                encoded += str(c)
        print(encoded)

    def send_response(self, s):
        sys.stdout.write(s + '\n')
        sys.stdout.flush()

    def send_responses(self, *response_strs):
        for response in response_strs:
            self.send_response(response)
        sys.stdout.flush()

    def log(self, *logstrs):
        for log in logstrs:
            print(log, file=sys.stderr)
        sys.stderr.flush()

    @staticmethod
    def main():
        DmgServer().log("Waiting for client to connect to DMG server...")
        
        input_reader = BufferedReader(InputStreamReader(sys.stdin))
        
        try:
            open_line = input_reader.readline()
            if not open_line: #TODO handle invalid initial command???
                return
            
            if not open_line.startswith('open '):
                return
            path = parse_line(open_line)
            
            file_path = os.path.join(os.getcwd(), path)
            if not os.path.exists(file_path):  # TODO handle files that do not exist

                pass
                
            try:
                provider = GByteProvider(file_path)
                dmg_file_reader = DmgFileReader(provider)

                dmg_file_reader.open()
                
                while True:
                    line = input_reader.readline()
                    if not line: 
                        break
                    parts = line.split('  ', 1)
                    
                    if len(parts) < 1:
                        continue
                    
                    cmd = parts[0]
                    
                    if cmd == 'close':
                        DmgServer().log("Exiting DMG server process: close cmd")
                        return
                        
                    elif cmd == 'get_listing': 
                        path = parse_line(line)
                        
                        listing = dmg_file_reader.get_listing(path)
                        self.send_response(str(len(listing)))  # write total number of children
                        for child_entry in listing:
                            DmgServer().writeln(child_entry.name)  # write name of each child
                            self.send_responses(str(child_entry.is_folder()), str(dmg_file_reader.get_length(child_entry)))
                            
                    elif cmd == 'get_info': 
                        path = parse_line(line)
                        
                        info_list = dmg_file_reader.get_info(path)
                        self.send_response(str(len(info_list)))  # write total number of info lines
                        for info in info_list:
                            self.send_response(info)  # write each info line

                    elif cmd == 'get_data': 
                        path = parse_line(line)

                        file_path = os.path.join(os.getcwd(), path)
                        
                        if not os.path.exists(file_path):  # TODO handle files that do not exist
                            
                            pass
                        
                        else:
                            expected_file_length = dmg_file_reader.get_length(path)
                            
                            try:
                                with open(file_path, 'rb') as f:
                                    data_stream = f.read()
                                    
                                self.send_response(str(len(data_stream)))  # write the length of the file

                            except Exception as e:
                                DmgServer().log("Error reading file: " + str(e))
                                
            except IOError as e:
                DmgServer().log("IOException error in DMGServer command processing: " + e.message)
                print(str(e), file=sys.stderr)

        finally:
            DmgServer().log("DMG server has terminated.")

    @staticmethod
    def parse_line(open_line):
        space = open_line.find('  ')
        path = open_line[space+1:].strip()
        return path

if __name__ == "__main__":
    DmgServer.main()

```

Note: This Python code is not a direct translation of the Java code. It's an attempt to replicate the functionality in Python, but it may not be identical due to differences between languages and libraries.