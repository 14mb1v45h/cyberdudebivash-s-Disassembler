# cyberdudebivash's Disassembler

A simple, educational Python-based tool for basic disassembly, decoding, and reverse engineering of application files. This tool provides a graphical user interface (GUI) to browse and analyze files in formats like .exe, .bin, .msi, .run, and .msix. It performs basic operations such as hex dumping, header parsing (e.g., PE for executables, properties for MSI), and a rudimentary disassembly assuming x86 architecture.

**Note:** This is a foundational, toy-level tool for learning purposes only. It does not perform full decompilation to source code (which is often impossible without original sources) or advanced reverse engineering. For professional use, rely on tools like Ghidra, IDA Pro, Binary Ninja, or Radare2.

## Features
- **File Browsing:** Select files via a GUI file dialog.
- **Basic Analysis:**
  - Displays file path and size.
  - Hex dump of the first 128 bytes.
  - PE header parsing for .exe and .bin files (detects machine type like x86/x64).
  - MSI/MSIX property extraction (requires msilib on Windows).
  - Simple disassembly of assumed code sections (limited to a few x86 opcodes).
- **Supported Formats:** .exe, .bin, .msi, .run, .msix.
- **Safety Warnings:** Analyze files in a virtual machine to avoid risks from malware.

## Installation
1. Ensure you have Python 3.x installed (tested on Python 3.12).
2. Clone or download the repository:

git clone <repository-url>
cd cyberdudebivash-disassembler</repository-url>

3. Install dependencies (if any) from `requirements.txt`:

pip install -r requirements.txt

- Note: This tool uses only standard Python libraries, so no external dependencies are required. msilib is optional and available in standard Python on Windows.

## Usage
1. Run the script:

python cyberdudebivash_disassembler.py

2. In the GUI:
- Click "Browse File" to select a supported file.
- The output will appear in the scrolled text area, including file info, hex dump, headers, and basic disassembly (where applicable).
3. Example Output:
- For an .exe: Shows PE headers and simplistic disassembly.
- For an .msi: Extracts properties like ProductName and Manufacturer.

## Limitations
- **Disassembly:** Extremely basic; only handles a handful of x86 opcodes with no full operand parsing or support for other architectures (e.g., ARM, x64 specifics).
- **Decompilation:** Does not reconstruct high-level source code (e.g., C++/Java); binaries lose this information during compilation.
- **Format Handling:** Minimal for .run (self-extracting archives) and .msix (ZIP-based; manual extraction recommended).
- **No Advanced Features:** Lacks debugging, deobfuscation, or integration with professional disassemblers.
- **Platform:** GUI requires Tkinter (standard in most Python installs). MSI parsing is Windows-only via msilib.
- **Security:** Do not analyze untrusted files on your main system; use a sandbox or VM.

## Contributing
Contributions are welcome! Feel free to submit pull requests for enhancements, such as adding more opcodes, supporting additional formats, or integrating external libraries like Capstone for better disassembly.

## License
This project is licensed under the MIT License. See the LICENSE file for details (if not present, assume standard MIT terms).

## Author
Developed by cyberdudebivash (copyright@cyberdudebivash @2025).