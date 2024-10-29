from tkinter import ttk, Menu, filedialog, messagebox, scrolledtext
import tkinter as tk
import datetime
import json

# Worse code ever 
class VMAnalyzer:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VMcrypt Analyzer")
        self.root.geometry("1200x800")
        self.root.configure(bg="#1e1e1e")
        self.opcodes = {
            0x01: "Load immediate value into a register.",
            0x02: "Load value from a register.",
            0x03: "Load value from memory into a register.",
            0x04: "Store value from register into memory.",
            0x10: "Add values in two registers and store result in the first register.",
            0x11: "Subtract value in one register from another.",
            0x12: "Multiply values in two registers.",
            0x13: "Divide value in one register by another.",
            0x14: "Modulus of value in one register by another.",
            0x20: "XOR values in two registers.",
            0x21: "OR values in two registers.",
            0x22: "AND values in two registers.",
            0x23: "NOT operation on a register.",
            0x24: "Shift left operation on a register.",
            0x25: "Shift right operation on a register.",
            0x26: "Rotate left operation on a register.",
            0x27: "Rotate right operation on a register.",
            0x30: "Jump to a specific memory address.",
            0x31: "Jump if zero in a register.",
            0x32: "Jump if not zero in a register.",
            0x40: "Push value in register to stack.",
            0x41: "Pop value from stack into register.",
            0x50: "Substitute value in register using S-box.",
            0x51: "Permute bits in a register.",
            0x52: "Inverse S-box substitution.",
            0x53: "Inverse permutation.",
            0xFF: "Halt the virtual machine execution.",
        }
        self.search_results = []
        self.memory_data = {}
        self.stack_data = []
        self.register_data = []
        self.opcode_history = []
        self.decoded_messages = []
        self.ip_data = []
        self.context_menu = Menu(root, tearoff=0)
        for label, encoding in [("Decode as ASCII", "ascii"), ("Decode as UTF-8", "utf-8"), ("Decode as Integer", "int"), ("Decode as Hex", "hex")]:
            self.context_menu.add_command(label=label, command=lambda enc=encoding: self.decode_selected(enc))
        self.create_widgets()

    def create_widgets(self) -> None:
        style = ttk.Style()
        style.configure("TButton", font=("Helvetica", 10), padding=5, background="#0C0C0C", foreground="#0C0C0C")
        style.configure("TLabel", font=("Helvetica", 12), background="#2e2e2e", foreground="#ffffff")
        style.configure("TFrame", background="#2e2e2e")
        style.configure("TEntry", font=("Helvetica", 12), background="#333333", foreground="#0C0C0C")
    
        def create_button(parent, text, command, row, column, **grid_options):
            btn = ttk.Button(parent, text=text, command=command, style="TButton")
            btn.grid(row=row, column=column, sticky="ew", **grid_options)
            return btn
    
        self.top_frame = ttk.Frame(self.root)
        self.top_frame.pack(fill="x", padx=10, pady=5)
        self.center_frame = ttk.Frame(self.top_frame)
        self.center_frame.pack(pady=5)
    
        for text, row, col in [("Load VM Dump:", 0, 0), ("Search:", 0, 2)]:
            ttk.Label(self.center_frame, text=text, style="TLabel").grid(row=row, column=col, padx=5, pady=5)
        
        self.file_btn = create_button(self.center_frame, "Browse", self.load_file, 0, 1, padx=10)
        self.search_entry = ttk.Entry(self.center_frame, style="TEntry")
        self.search_entry.grid(row=0, column=3, padx=5, pady=5)
        self.search_entry.bind("<KeyRelease-Return>", lambda event: self.memory_search())
        ttk.Label(self.center_frame, text="  ", style="TLabel").grid(row=0, column=4, padx=5, pady=5)
    
        for text, cmd, col in [("Up", self.navigate_up, 5), ("Down", self.navigate_down, 6), ("Export Analysis", self.export_analysis, 7)]:
            create_button(self.center_frame, text, cmd, 0, col)
    
        self.filter_ascii_var = tk.BooleanVar()
        self.filter_ascii_check = ttk.Checkbutton(self.center_frame, text="Filter ASCII", variable=self.filter_ascii_var, command=self.show_memory)
        self.filter_ascii_check.grid(row=0, column=8, padx=10, pady=5)
    
        self.bottom_frame = ttk.Frame(self.root)
        self.bottom_frame.pack(fill="both", expand=True)
        self.history_frame = ttk.LabelFrame(self.bottom_frame, text="Opcode Execution History", style="TLabel")
        self.history_frame.pack(side="left", fill="y", padx=10, pady=10)
    
        self.history_text = scrolledtext.ScrolledText(self.history_frame, wrap=tk.NONE, bg="#1e1e1e", fg="#ffffff", highlightbackground="#444444", width=40)
        self.history_text.pack(fill="both", expand=True)
    
        self.history_h_scroll = ttk.Scrollbar(self.history_frame, orient="horizontal", command=self.history_text.xview)
        self.history_h_scroll.pack(side="bottom", fill="x")
        self.history_text.config(xscrollcommand=self.history_h_scroll.set)
    
        self.details_frame = ttk.Frame(self.bottom_frame)
        self.details_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)
        for text, cmd, col in [("Inspect Memory", self.show_memory, 0), ("Inspect Stack", self.show_stack, 1), ("Inspect Registers", self.show_registers, 2), ("Decoded Messages", self.show_decoded, 3), ("Inspect IP", self.show_ip, 4)]:
            create_button(self.details_frame, text, cmd, 0, col)
    
        self.details_text = scrolledtext.ScrolledText(self.details_frame, wrap=tk.NONE, bg="#1e1e1e", fg="#ffffff", highlightbackground="#444444")
        self.details_text.grid(row=1, column=0, columnspan=6, padx=10, pady=5, sticky="nsew")
    
        self.details_h_scroll = ttk.Scrollbar(self.details_frame, orient="horizontal", command=self.details_text.xview)
        self.details_h_scroll.grid(row=2, column=0, columnspan=6, sticky="ew")
        self.details_text.config(xscrollcommand=self.details_h_scroll.set)
    
        self.details_text.bind("<Button-3>", self.show_context)
        for i in range(6):
            self.details_frame.grid_columnconfigure(i, weight=1)
        self.details_frame.grid_rowconfigure(1, weight=1)

    def load_file(self) -> None:
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if not file_path: return
        self.history_text.delete(1.0, tk.END)
        self.details_text.delete(1.0, tk.END)
        self.memory_data.clear()
        self.stack_data.clear()
        self.register_data.clear()
        self.opcode_history.clear()
        self.decoded_messages.clear()

        with open(file_path, "r") as file:
            for state in file.read().split("--- State")[1:]:
                self.process_state(state.strip())

        self.show_summary()

    def process_state(self, state_text: str) -> None:
        lines = state_text.splitlines()
        opcode_line = next((line for line in lines if line.startswith("Opcode:")), None)
        ip_line = next((line for line in lines if line.startswith("IP:")), None)

        if not opcode_line:
            self.details_text.insert(tk.END, state_text + "\n\n")
            return

        opcode = int(opcode_line.split(": ")[1], 16)
        opcode_desc = self.opcodes.get(opcode, "Unknown operation")
        state_summary = f"{opcode_desc} ({hex(opcode)})\n"

        if ip_line:
            ip_value = int(ip_line.split(": ")[1])
            self.ip_data.append(ip_value)

        for line in lines:
            if line.startswith("Registers:"):
                self.register_data.append(line.split("rs")[1])
            elif line.startswith("Stack:"):
                stacks = line.split(": ")[1]
                self.stack_data.append(stacks)
                decoded_text = self.decode_values(stacks)
                if decoded_text:
                    self.decoded_messages.append([stacks, decoded_text])
            elif line.startswith("Memory"):
                self.memory_data[len(self.memory_data)] = line.split(": ")[1]
            state_summary += line + "\n"

        self.opcode_history.append(state_summary)
        self.history_text.insert(tk.END, state_summary + "\n\n")

    def show_ip(self) -> None:
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Instruction Pointer (IP) Values:\n")
        for i, ip_value in enumerate(self.ip_data):
            self.details_text.insert(tk.END, f"Step {i + 1} - IP: {ip_value}\n")

    def decode_values(self, values: str, encoding: str = "utf-8") -> str:
        try:
            value_list = values.strip('[]').split(',') if values.startswith('[') and values.endswith(']') else values.split()
            byte_values = bytes(int(v.strip()) for v in value_list if v.strip().isdigit() and 0 <= int(v.strip()) <= 255)
            
            decoding_functions = {
                "ascii": lambda: byte_values.decode("ascii", errors="ignore"),
                "utf-8": lambda: byte_values.decode("utf-8", errors="ignore"),
                "int": lambda: [int(b) for b in byte_values],
                "hex": lambda: byte_values.hex()
            }
            
            return decoding_functions.get(encoding, lambda: None)()
        except Exception as e:
            messagebox.showerror("Decoding Error", f"Could not decode values: {e}")
            print(e)
            return None

    def decode_selected(self, encoding: str = "utf-8") -> None:
        try:
            selected_text = self.details_text.selection_get()
            decoded = self.decode_values(selected_text, encoding)
            if decoded:
                index = self.details_text.index(tk.SEL_LAST)
                self.details_text.insert(index, f" (Decoded as {encoding}: {decoded})")
            else:
                messagebox.showinfo("Decode", f"Could not decode selected text as {encoding}.")
        except tk.TclError:
            messagebox.showwarning("Decode", "No text selected for decoding.")

    def show_context(self, event: tk.Event) -> None:
        try:
            self.context_menu.post(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def show_memory(self) -> None:
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Memory Contents (Hex & ASCII):\n\n")
        filter_ascii = self.filter_ascii_var.get()
        for addr, content in self.memory_data.items():
            hex_chunks = [content[i:i + 32] for i in range(0, len(content), 32)]
            for chunk in hex_chunks:
                ascii_representation = ''.join(chr(int(chunk[i:i + 2], 16)) if len(chunk[i:i + 2]) == 2 and chunk[i:i + 2].isalnum() and 32 <= int(chunk[i:i + 2], 16) <= 126 else '.' for i in range(0, len(chunk), 2))
                if filter_ascii and all(c == '.' for c in ascii_representation):
                    continue
                formatted_address = f"Address {addr:08X}"
                hex_view = ' '.join([chunk[i:i + 2] for i in range(0, len(chunk), 2)])
                memory_line = f"{formatted_address}: {hex_view:<48} | {ascii_representation}\n"
                self.details_text.insert(tk.END, memory_line)
        self.details_text.tag_configure("highlight", background="yellow", foreground="black")

    def memory_search(self) -> None:
        query = self.search_entry.get()
        if not query:
            messagebox.showwarning("No Query", "Please enter a value to search in memory.")
            return

        self.details_text.tag_remove("highlight", "1.0", tk.END)
        self.details_text.tag_remove("active_highlight", "1.0", tk.END)
        self.search_results = []
        hex_search = query if all(c in "0123456789abcdefABCDEF" for c in query) else query.encode().hex()

        start_index = "1.0"
        while (start_index := self.details_text.search(hex_search, start_index, tk.END)):
            end_index = f"{start_index}+{len(hex_search)}c"
            self.details_text.tag_add("highlight", start_index, end_index)
            self.search_results.append((start_index, end_index))
            start_index = end_index

        if self.search_results:
            self.current_index = 0
            self.highlight_result()
        else:
            messagebox.showinfo("Not Found", f"No instances of '{query}' found in memory.")

    def highlight_result(self):
        self.details_text.tag_remove("active_highlight", "1.0", tk.END)
        if self.search_results:
            start, end = self.search_results[self.current_index]
            self.details_text.tag_add("active_highlight", start, end)
            self.details_text.see(start)
            self.details_text.tag_configure("highlight", background="yellow", foreground="black")
            self.details_text.tag_configure("active_highlight", background="orange", foreground="black")

    def navigate_up(self):
        if self.search_results and self.current_index > 0:
            self.current_index -= 1
            self.highlight_result()

    def navigate_down(self):
        if self.search_results and self.current_index < len(self.search_results) - 1:
            self.current_index += 1
            self.highlight_result()

    def show_stack(self):
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Stack Contents:\n")
        for i, stack_values in enumerate(self.stack_data):
            self.details_text.insert(tk.END, f"Step {i + 1} - Stack: {stack_values}\n")

    def show_registers(self):
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Register Contents:\n")
        for i, reg_values in enumerate(self.register_data):
            self.details_text.insert(tk.END, f"Step {i + 1} - Registers: {reg_values}\n")

    def show_decoded(self):
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "Decoded Messages:\n")
        for message in self.decoded_messages:
            self.details_text.insert(tk.END, f"{message[0]} -> {message[1]}\n")

    def show_summary(self):
        self.details_text.delete(1.0, tk.END)
        self.details_text.insert(tk.END, "\nExecution Summary:\n")
        for i, summary in enumerate(self.opcode_history):
            self.details_text.insert(tk.END, f"Step {i + 1}:\n{summary}\n")

    def export_analysis(self):
        date = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_path = filedialog.asksaveasfilename(defaultextension=f"{date}.json", filetypes=[("JSON files", "*.json"), ("Text files", "*.txt")])
        if file_path:
            analysis_data = {"opcode_history": self.opcode_history, "decoded_messages": self.decoded_messages}
            with open(file_path, "w") as f:
                json.dump(analysis_data, f, indent=4)
            messagebox.showinfo("Export", f"Analysis exported to {file_path}")

root = tk.Tk()
app = VMAnalyzer(root)
root.mainloop()