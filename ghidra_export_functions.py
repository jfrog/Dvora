import json
from ghidra.program.model.listing import FunctionManager

output_file = "functions_addresses.json" # Define the path to the output file

fm = currentProgram.getFunctionManager()
functions = fm.getFunctions(True)

functions_data = {}

for func in functions:
    addr = str(func.getEntryPoint())
    functions_data[func.getName()] = addr

# Write data to json file.
with open(output_file, "w") as json_file:
    json.dump(functions_data, json_file, indent=4)

print("Function addresses saved to:", output_file)
