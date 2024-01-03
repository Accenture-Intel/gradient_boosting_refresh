from .utils import run_with_output
import tempfile
from .utils import get_time_string
import logging
from . import constants

log = logging.getLogger(constants.LOGGER_NAME)

class EbpfAnalyzer:
    def __init__(self) -> None: 
        enabled_functions = None
        kernel_configurations = None
    
    def write_to(self, source_path, destination_path) -> None:
        try:
            # Open the source file for reading
            with open(source_path, 'r' , errors='ignore') as source_file:
                file_contents = source_file.read()

            # Open the destination file for writing
            with open(destination_path, 'w', errors='ignore') as destination_file:
                destination_file.write(file_contents)
                self.kernel_configurations = destination_path
        except Exception as e:
            log.error(f"An error occurred while writing to the file: {e}")
        

    def collect_kernel_configurations(self) -> None:
        command = 'uname -r'
        kernel_version = run_with_output(command)
        path = "/boot/config-"+kernel_version
        _ , kernel_config_path = tempfile.mkstemp(prefix=f'ebpf_kernel_config_{get_time_string()}', suffix='.txt')
        self.write_to(path, kernel_config_path)
        return 
    
    def collect_enabled_functions(self) -> None:
        enabled_functions_content = self.get_ebpf_enabled_functions()
        _ , enabled_functions_path = tempfile.mkstemp(prefix=f'ebpf_enabled_func_{get_time_string()}', suffix='.txt')
        with open(enabled_functions_path, 'w', errors='ignore') as destination_file:
            destination_file.write(enabled_functions_content)
            self.enabled_functions = enabled_functions_path
    
    def get_ebpf_enabled_functions(self):
        command = 'sudo cat /sys/kernel/debug/tracing/enabled_functions'
        return run_with_output(command)
            


        
     
