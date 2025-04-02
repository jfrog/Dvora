Readme
# Dvora

## Overview
Dvora is an open-source Python tool designed to divinate and classify unknown functions for Static Application Security Testing (SAST) of binary files. It can be used by static tools (or during manual research) to recognize common library functions which are statically linked into the analyzed binary (and not dynamically loaded).

Failing to recognize library functions may lead to misdetecting common and severe vulnerabilities, both in manual and in automated static analysis.

For instance, when compiling a binary file as a statically linked executable without symbols, there may be no import table or symbols available to indicate which functions exist. Additionally, when compiling a binary file as a dynamically linked executable, the compiler may choose to inline certain functions, further obscuring their presence and complicating the identification process for SAST tools.

Source code scanning is not a sufficient alternative either—often, the source code is not available, or dangerous functions may be added under different names or only during the build process.

Dvora is based on another open-source tool, Sibyl ,but is based on a more modern infrastructure (Unicorn) among other advantages allowing for a broader platform support.

Fun fact: Since Dvora is a divination tool, it is named after Deborah the prophet :)

## Features
Function Identification: Detects and identifies function calls even when names are obscured or inlined.
Compatibility: Works with both statically and dynamically linked binaries.
Open Source: Freely available for modification and contributions from the community.

## Requirements
Python 3
Poetry (Python package manager)

## Execution
Clone the repository using the command:

```
git clone https://github.com/jfrog/Dvora.git
```

If you don’t have Poetry installed, use the command:
```
pip install poetry
```

Execute the following commands to install all dependencies:
```
poetry shell
poetry install
```

To run Dvora, execute:
```
python3 demo.py <binary_file> <function_address>
```

Where:
- binary_file: The binary file you want to examine.
- function_address: The address of the function you want to examine.

Example:
```
python3 demo.py /path/to/binary 401745
```

## How to Find Function Addresses?
You can use Ghidra to examine function addresses. 

You can also export functions addresses using the Jython script (included in this repository) named `ghidra_export_functions.py`.

## Upcoming Releases
We are continuously expanding this repository with new supported functionalities. 

Stay tuned for additional releases based on our latest research!

## How to Contribute
We invite the security community to contribute to this initiative. 

Feel free to submit an issue or a pull request. 

## License
This project is licensed under the **GNU GPL 3.0**.

## Contact
For inquiries or collaboration, please reach out to us via [GitHub Issues](https://github.com/jfrog/Dvora/issues).

## Repository URL
🔗 [GitHub Repository](https://github.com/jfrog/Dvora)

