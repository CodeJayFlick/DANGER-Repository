import os
import platform
from tkinter import filedialog, messagebox

class CreatePdbXmlFilesScript:
    def run(self):
        if not self.is_running_on_windows():
            messagebox.showerror("Error", "This script can only be run on Windows.")
            return
        
        pdb_exe_location = Application.get_pdb_exe_path()
        
        choices = ["single file", "directory of files"]
        choice = ask_choice("PDB file or directory",
                             "Would you like to operate on a single .pdb file or a directory of .pdb files?",
                             *choices)
        
        if choice == choices[0]:
            pdb_file = self.ask_file("Choose a PDB file", "OK")
            
            if not os.path.exists(pdb_file):
                messagebox.showerror(f"Error: {pdb_file} is not a valid file.")
                return
            
            if not pdb_file.endswith(".pdb"):
                messagebox.showerror("Aborting: Expected input file to have extension of type .pdb (got '" + pdb_file + "').")
                return
            
            self.process_pdb(pdb_exe_location, os.path.dirname(pdb_file), os.path.basename(pdb_file), pdb_file)
        else:
            pdb_dir = self.ask_directory("Choose PDB root folder (performs recursive search for .pdb files)", "OK")
            
            # Get list of files to process
            found_files = []
            self.get_pdb_files(pdb_dir, found_files)
            
            created_files_counter = 0
            
            for child_pdb_file in found_files:
                pdb_parent_dir = os.path.dirname(child_pdb_file)
                pdb_name = os.path.basename(child_pdb_file)
                
                current_file_path = child_pdb_file
                print(f"Processing: {current_file_path}")
                
                self.run_pdb_exe(pdb_exe_location, pdb_parent_dir, pdb_name, current_file_path)
                
                created_files_counter += 1
                
                if messagebox.askokcancel("Cancel", "Do you want to cancel the process?"):
                    break
            
            print(f"Created {created_files_counter} .pdb.xml file(s).")
        
    def is_running_on_windows(self):
        return platform.system() == 'Windows'
    
    def ask_file(self, title, prompt):
        root = tkinter.Tk()
        root.withdraw()
        return filedialog.askopenfilename(title=title, prompt=prompt)
    
    def ask_directory(self, title, prompt):
        root = tkinter.Tk()
        root.withdraw()
        return filedialog.askdirectory(title=title, prompt=prompt)
    
    def process_pdb(self, pdb_exe_location, pdb_parent_dir, pdb_name, current_file_path):
        print(f"Processing: {current_file_path}")
        
        try:
            # Run PDB.exe
            builder = ProcessBuilder([pdb_exe_location, current_file_path])
            created_file = os.path.join(pdb_parent_dir, f"{os.path.basename(current_file_path)}.xml")
            builder.redirectOutput(Files.newOutputStream(created_file))
            
            process = builder.start()
            str_builder = StringBuilder()
            
            reader = BufferedReader(InputStreamReader(process.getErrorStream()))
            line = None
            
            while (line := reader.readLine()) is not None:
                str_builder.append(line)
                str_builder.append(os.linesep)
            
            reader.close()
            
            exit_value = process.waitFor()
            error_message = str_builder.toString()
            
            if error_message.length() > 0:
                if os.path.exists(created_file):
                    os.remove(created_file)
                
                raise IOException(f"At file '{pdb_name}':\n{error_message}")
            
            if exit_value != 0:
                if os.path.exists(created_file):
                    os.remove(created_file)
                
                raise IOException(f"At file '{pdb_name}':\nAbnormal termination of 'pdb.exe' process.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
    
    def get_pdb_files(self, parent_dir, found_files):
        for child_file in os.listdir(parent_dir):
            if os.path.isdir(os.path.join(parent_dir, child_file)):
                self.get_pdb_files(os.path.join(parent_dir, child_file), found_files)
            elif child_file.endswith(".pdb"):
                found_files.append(os.path.join(parent_dir, child_file))
