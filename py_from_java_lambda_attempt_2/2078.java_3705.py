Here is the translation of the Java code into Python:

```Python
import subprocess
import threading
from typing import List

class HelloWorld:
    @staticmethod
    def main(args):
        print("Hello, World!")

def test_arguments():
    vmm = Bootstrap.virtual_machine_manager()
    conn = vmm.default_connector()
    args = conn.default_arguments()
    print(f"Args: {args}")
    
def test_simple_launch():
    vmm = Bootstrap.virtual_machine_manager()
    conn = vmm.default_connector()
    args = conn.default_arguments()
    args["options"] = f"-cp \"{sys.getProperty('java.class.path')}\""
    args["main"] = HelloWorld.__name__
    vm = conn.launch(args)
    
    for event in vm.event_queue().remove(1000):
        print(f"Event: {event}")
        assert isinstance(event, VMStartEvent)
        
    print(vm.version())
    print(vm.description())
    print(vm.name())
    
    vm.resume()
    
    reader = BufferedReader(InputStreamReader(vm.process().get_input_stream()))
    hw = reader.readline()
    assert hw == "Hello, World!"
    
    vm.dispose()

def test_simple_socket_attach_jdwp():
    # Launch a VM so that we have an "existing process"
    pb = subprocess.Popen(["java", "-agentlib:jdwp=transport=dt_socket,address=0,server=y,suspend=y", f"-cp {sys.getProperty('java.class.path')}", HelloWorld.__name__], stdout=subprocess.PIPE)
    
    # The JDWP Agent will print the open port before suspending
    reader = BufferedReader(InputStreamReader(pb.stdout))
    listen_line = reader.readline()
    print(listen_line)
    assert listen_line.startswith("Listening")
    parts = listen_line.split("\\s+")
    port = parts[-1]
    
    # OK, everything above simulates existing process, now the real connection begins
    
    tcp_conn = vmm.attaching_connectors().stream().filter(c => c.default_arguments().contains_key("hostname")).findFirst().orElse(None)
    args = tcp_conn.default_arguments()
    args["hostname"] = "localhost"
    args["port"] = port
    vm = tcp_conn.attach(args)
    
    for event in vm.event_queue().remove(1000):
        print(f"Event: {event}")
        assert isinstance(event, VMStartEvent)
        
    vm.resume()
    
    reader = BufferedReader(InputStreamReader(pb.stdout))
    hw = reader.readline()
    assert hw == "Hello, World!"
    
    vm.dispose()

def test_simple_process_attach_jdwp():
    # Launch a VM so that we have an "existing process"
    pb = subprocess.Popen(["java", "-agentlib:jdwp=transport=dt_socket,address=0,server=y,suspend=y", f"-cp {sys.getProperty('java.class.path')}", HelloWorld.__name__], stdout=subprocess.PIPE)
    
    # The JDWP Agent will print the open port before suspending
    reader = BufferedReader(InputStreamReader(pb.stdout))
    listen_line = reader.readline()
    print(listen_line)
    
    # OK, everything above simulates existing process, now the real connection begins
    
    proc_conn = vmm.attaching_connectors().stream().filter(c => c.default_arguments().contains_key("pid")).findFirst().orElse(None)
    args = proc_conn.default_arguments()
    args["pid"] = str(pb.pid())
    vm = proc_conn.attach(args)
    
    for event in vm.event_queue().remove(1000):
        print(f"Event: {event}")
        assert isinstance(event, VMStartEvent)
        
    vm.resume()
    
    reader = BufferedReader(InputStreamReader(pb.stdout))
    hw = reader.readline()
    assert hw == "Hello, World!"
    
    vm.dispose()

def test_simple_listen_attach_jdwp():
    l_conn = vmm.listening_connectors().stream().filter(c => c.default_arguments().contains_key("localAddress")).findFirst().orElse(None)
    args = l_conn.default_arguments()
    args["port"] = "0"
    args["localAddress"] = "localhost"
    addr = l_conn.start_listening(args)
    
    pb = subprocess.Popen(["java", "-agentlib:jdwp=transport=dt_socket,address=" + addr + ",server=n,suspend=y", f"-cp {sys.getProperty('java.class.path')}", HelloWorld.__name__], stdout=subprocess.PIPE)
    
    vm = l_conn.accept(args)
    
    for event in vm.event_queue().remove(1000):
        print(f"Event: {event}")
        assert isinstance(event, VMStartEvent)
        
    vm.resume()
    
    reader = BufferedReader(InputStreamReader(pb.stdout))
    hw = reader.readline()
    assert hw == "Hello, World!"
    
    vm.dispose()

def test_attach_jdwp():
    tcp_conn = vmm.attaching_connectors().stream().filter(c => c.default_arguments().contains_key("hostname")).findFirst().orElse(None)
    args = tcp_conn.default_arguments()
    args["hostname"] = "localhost"
    args["port"] = "8000"
    vm = tcp_conn.attach(args)
    
    print(f"Version: {vm.version()}")
    print(f"Description: {vm.description()}")
    print(f"Name: {vm.name()}")

def test_what_is_code_index():
    vmm = Bootstrap.virtual_machine_manager()
    conn = vmm.default_connector()
    args = conn.default_arguments()
    args["options"] = f"-cp \"{sys.getProperty('java.class.path')}\""
    args["main"] = HelloWorld.__name__
    
    vm = conn.launch(args)
    
    for event in vm.event_queue().remove(1000):
        print(f"Event: {event}")
        assert isinstance(event, VMStartEvent)
        
    print("Resuming with request")
    
    cp_req = vm.event_request_manager().create_class_prepare_request()
    cp_req.enable()
    
    vm.resume()
    
    until_hw = True
    while until_hw:
        for event in vm.event_queue().remove(1000):
            if isinstance(event, ClassPrepareEvent):
                print(f"  Type: {event.reference_type()}")
                if event.reference_type().__name__.contains(HelloWorld.__name__):
                    break until_hw
        
        cp_req.disable()
        
    hw_classes = vm.classes_by_name(HelloWorld.__name__)
    
    assert len(hw_classes) == 1
    
    hw_class = hw_classes[0]
    hw_main_methods = hw_class.methods_by_name("main")
    
    assert len(hw_main_methods) == 1
    hw_main_method = hw_main_methods[0]
    
    print(f"Code: {NumericUtilities.convert_bytes_to_string(hw_main_method.bytecodes())}")
    
    bp_main_req = vm.event_request_manager().create_breakpoint_request(hw_main_method.location())
    bp_main_req.enable()
    
    thread = None
    
    while True:
        for event in vm.event_queue().remove(1000):
            if isinstance(event, BreakpointEvent):
                print(f"Event: {event}")
                thread = event.thread
                break
        
        step_req = vm.event_request_manager().create_step_request(thread, StepRequest.STEP_MIN, StepRequest.STEP_INTO)
        step_req.enable()
        
        while True:
            location = thread.frame(0).location
            
            if location.method() == hw_main_method:
                print(f"Mth={location.method()},Idx={location.code_index()}")
                vm.resume()
            
            else:
                break
        
        step_req.disable()
    
    reader = BufferedReader(InputStreamReader(vm.process().get_input_stream()))
    hw = reader.readline()
    assert hw == "Hello, World!"
```

Please note that this code is a direct translation of the Java code and may not work as expected. The Python code does not have an equivalent to Java's `Bootstrap` class or JDWP (Java Debug Wire Protocol) which are used in the original Java code for launching and attaching to JVM processes.