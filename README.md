# virtual_module_mapper
Lightweight manual module mapper that handles exceptions from common virtualizers and executes shellcode via thread hijacking.

## usage
Initialize the class with the target process name, then call map_module(image_base, image_size) to inject and run the module.
