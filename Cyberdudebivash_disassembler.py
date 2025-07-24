import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import binascii
import struct

# Simple x86 opcode map for basic disassembly (very limited, for demonstration purposes only)
# This covers only a few common opcodes; a real disassembler would use libraries like Capstone.
X86_OPCODES = {
    b'\x55': 'push ebp',
    b'\x89\xe5': 'mov ebp, esp',
    b'\x8b': 'mov',  # Simplified, needs operand parsing in a real tool
    b'\xc3': 'ret',
    b'\x90': 'nop',
    b'\xeb': 'jmp short',  # Relative jump
    # Expand this dictionary for more accuracy, but this is toy-level
}

def read_pe_headers(file_path):
    """Basic PE header parser for .exe files."""
    try:
        with open(file_path, 'rb') as f:
            # Read DOS header
            dos_header = f.read(64)
            if dos_header[:2] != b'MZ':
                return "Not a valid PE file (missing MZ signature)."
            e_lfanew = struct.unpack('<I', dos_header[60:64])[0]
            f.seek(e_lfanew)
            pe_header = f.read(24)
            if pe_header[:4] != b'PE\x00\x00':
                return "Not a valid PE file (missing PE signature)."
            machine = struct.unpack('<H', pe_header[4:6])[0]
            machine_type = {0x14c: 'x86', 0x8664: 'x64'}.get(machine, 'Unknown')
            return f"PE file detected. Machine type: {machine_type}"
    except Exception as e:
        return f"Error parsing PE headers: {str(e)}"

def extract_msi_info(file_path):
    """Basic MSI info extraction if msilib is available (standard in Windows Python)."""
    try:
        import msilib
        db = msilib.OpenDatabase(file_path, msilib.MSIDBOPEN_READONLY)
        view = db.OpenView("SELECT * FROM Property")
        view.Execute(None)
        properties = {}
        record = view.Fetch()
        while record:
            prop = record.GetString(1)
            value = record.GetString(2)
            properties[prop] = value
            record = view.Fetch()
        return f"MSI Properties: {properties}"
    except ImportError:
        return "msilib not available for MSI parsing."
    except Exception as e:
        return f"Error parsing MSI: {str(e)}"

def simple_disassemble(binary_data, start=0, length=200):
    """Very basic disassembly attempt assuming x86 code. Not production-ready."""
    disasm = []
    i = start
    end = min(start + length, len(binary_data))
    while i < end:
        matched = False
        for op_len in range(1, 3):  # Check for 1-2 byte opcodes
            op = binary_data[i:i+op_len]
            if op in X86_OPCODES:
                mnemonic = X86_OPCODES[op]
                # Simplistic operand handling for some
                if mnemonic == 'mov' and i + op_len + 2 <= end:
                    operand = binary_data[i+op_len:i+op_len+2].hex()
                    mnemonic += f" [operands: {operand}]"
                disasm.append(f"{i:08x}: {mnemonic}")
                i += op_len + (2 if mnemonic.startswith('mov') else 0)  # Skip operands roughly
                matched = True
                break
        if not matched:
            disasm.append(f"{i:08x}: db {binary_data[i:i+1].hex()}")
            i += 1
    return "\n".join(disasm)

def browse_file():
    file_path = filedialog.askopenfilename(
        title="Select Application File",
        filetypes=[("Supported Files", "*.exe *.bin *.msi *.run *.msix"), ("All Files", "*.*")]
    )
    if file_path:
        file_label.config(text=f"Selected: {os.path.basename(file_path)}")
        output_text.delete(1.0, tk.END)
        try:
            with open(file_path, 'rb') as f:
                binary_data = f.read()
            
            # Display basic file info
            file_size = len(binary_data)
            output_text.insert(tk.END, f"File Path: {file_path}\nSize: {file_size} bytes\n\n")
            
            # Hex Dump of first 128 bytes
            hex_dump = binascii.hexlify(binary_data[:128]).decode('utf-8')
            formatted_hex = ' '.join(hex_dump[j:j+2] for j in range(0, len(hex_dump), 2))
            output_text.insert(tk.END, f"Hex Dump (first 128 bytes):\n{formatted_hex}\n\n")
            
            # File-type specific handling
            ext = os.path.splitext(file_path)[1].lower()
            if ext == '.exe' or ext == '.bin':
                pe_info = read_pe_headers(file_path)
                output_text.insert(tk.END, f"Header Info: {pe_info}\n\n")
                # Assume code starts after headers (simplistic offset)
                code_start = 0x400  # Rough guess for .exe code section
                disasm = simple_disassemble(binary_data, start=code_start)
                output_text.insert(tk.END, f"Basic Disassembly (assuming x86, limited):\n{disasm}\n\n")
            elif ext == '.msi' or ext == '.msix':
                msi_info = extract_msi_info(file_path)
                output_text.insert(tk.END, f"MSI/MSIX Info: {msi_info}\n\n")
                # For MSIX, it's ZIP-based, but simplistic
                output_text.insert(tk.END, "Note: MSIX is a ZIP package; extract for further analysis.\n")
            elif ext == '.run':
                output_text.insert(tk.END, "RUN file detected (likely self-extracting). Basic hex shown.\n")
                # Could add shell extraction logic, but omitted for simplicity
            else:
                output_text.insert(tk.END, "Unsupported format for advanced analysis. Showing basic info only.\n")
            
            # General Note
            output_text.insert(tk.END, "Important Note: This tool provides basic analysis only. "
                                       "Full disassembly, decompilation, and reverse engineering require "
                                       "professional tools like Ghidra, IDA Pro, or Binary Ninja. "
                                       "Source code reconstruction from binaries is not fully possible "
                                       "without original sources, as compilation loses high-level info. "
                                       "Use this for educational purposes.\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to analyze file: {str(e)}")

# GUI Setup
root = tk.Tk()
root.title("cyberdudebivash's Disassembler & Reverse Engineering Tool")
root.geometry("800x600")

tk.Label(root, text="Browse Application Installer/File to Analyze:", font=("Arial", 12)).pack(pady=10)

browse_btn = tk.Button(root, text="Browse File", command=browse_file, width=20)
browse_btn.pack()

file_label = tk.Label(root, text="No file selected", fg="blue")
file_label.pack(pady=5)

output_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=90, height=30)
output_text.pack(pady=10)

root.mainloop()