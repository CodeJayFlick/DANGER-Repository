import ghidra_app_script as script
from ghidra.program.model import address, data, listing, mem, memory_block
from java.util import ArrayList, List

class FindImagesScript(script.GhidraScript):
    def run(self):
        num_valid_images_found = 0
        
        print("Looking for GIF and PNG images in " + self.current_program.get_name())
        
        found_gifs = scan_for_gif87a_images()
        found_gifs.extend(scan_for_gif89a_images())

        for i in range(len(found_gifs)):
            found_gif_image = False
            data_at_address = self.data_at(address=found_gifs[i])
            
            if data_at_address is None:
                print("Trying to apply GIF datatype at " + str(found_gifs[i]))
                
                try:
                    new_gif_data = create_data(address=found_gifs[i], data_type=GIFDataType())
                    
                    if new_gif_data is not None:
                        print("Applied GIF at " + str(new_gif_data.get_address_string(false, true)))
                        found_gif_image = True
                    else:
                        raise Exception("Invalid GIF")
                except Exception as e:
                    print("Invalid GIF at " + str(found_gifs[i]))
            
            elif data_at_address.get_mnemonic_string() == "GIF":
                print("GIF already applied at " + str(data_at_address.get_address_string(false, true)))
                found_gif_image = True
            
            if found_gif_image:
                print("Found GIF in program " + self.current_program.get_executable_path() + 
                      " at address " + str(found_gifs[i]))
                num_valid_images_found += 1
        
        for i in range(len(found_pngs)):
            found_png_image = False
            data_at_address = self.data_at(address=found_pngs[i])
            
            if data_at_address is None:
                print("Trying to apply PNG datatype at " + str(found_pngs[i]))
                
                try:
                    new_png_data = create_data(address=found_pngs[i], data_type=PngDataType())
                    
                    if new_png_data is not None:
                        print("Applied PNG at " + str(new_png_data.get_address_string(false, true)))
                        found_png_image = True
                    else:
                        raise Exception("Invalid PNG")
                except Exception as e:
                    print("Invalid PNG at " + str(found_pngs[i]))
            
            elif data_at_address.get_mnemonic_string() == "PNG":
                print("PNG already applied at " + str(data_at_address.get_address_string(false, true)))
                found_png_image = True
            
            if found_png_image:
                print("Found PNG in program " + self.current_program.get_executable_path() + 
                      " at address " + str(found_pngs[i]))
                num_valid_images_found += 1
        
        if num_valid_images_found == 0:
            print("No PNG or GIF images found in " + self.current_program.get_name())
        
    def data_at(self, address):
        return listing.Data.find(address)
    
    def scan_for_gif87a_images(self):
        gif_bytes = bytearray([0x47, 0x49, 0x46, 0x38, 0x37, 0x61])
        found_gifs = self.scan_for_images(gif_bytes)
        
        return found_gifs
    
    def scan_for_gif89a_images(self):
        gif_bytes = bytearray([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])
        found_gifs = self.scan_for_images(gif_bytes)
        
        return found_gifs
    
    def scan_for_pngs(self):
        png_bytes = bytearray([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])
        found_pngs = self.scan_for_images(png_bytes)
        
        return found_pngs
    
    def scan_for_images(self, image_bytes):
        memory = self.current_program.get_memory()
        blocks = memory.get_blocks()
        
        mask_bytes = None
        found_images = ArrayList(address())
        
        for i in range(len(blocks)):
            if blocks[i].is_initialized():
                start_address = blocks[i].get_start()
                
                while True:
                    found_address = memory.find_bytes(start=start_address, end=blocks[i].get_end(), 
                                                      bytes=image_bytes, mask_bytes=None, monitor=self)
                    
                    if found_address is not None:
                        found_images.add(found_address)
                        start_address += 1
                    else:
                        break
        
        return found_images

# Initialize the script with a Ghidra program.
script = FindImagesScript()
