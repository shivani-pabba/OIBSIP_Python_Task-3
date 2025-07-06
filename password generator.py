import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import pyperclip

def generate_password(length, use_letters, use_numbers, use_symbols):
    character_set = ''
    if use_letters:
        character_set += string.ascii_letters
    if use_numbers:
        character_set += string.digits
    if use_symbols:
        character_set += string.punctuation

    if not character_set:
        raise ValueError("At least one character type must be selected")

    if length <= 0:
        raise ValueError("Password length must be greater than 0")

    password = ''.join(random.choice(character_set) for _ in range(length))
    return password

def on_generate():
    try:
        length_str = length_entry.get()
        if not length_str.strip().isdigit():
            raise ValueError("Please enter a valid number for length.")
        length = int(length_str)
        
        use_letters = letters_var.get()
        use_numbers = numbers_var.get()
        use_symbols = symbols_var.get()
        
        password = generate_password(length, use_letters, use_numbers, use_symbols)
        result_var.set(password)
    except ValueError as e:
        messagebox.showerror("Error", str(e))

def on_copy():
    if not result_var.get():
        messagebox.showwarning("Warning", "Nothing to copy!")
        return
    pyperclip.copy(result_var.get())
    messagebox.showinfo("Info", "Password copied to clipboard")

def on_clear():
    length_entry.delete(0, tk.END)
    result_var.set("")
    show_password_var.set(False)
    result_entry.config(show="*")

def toggle_password_visibility():
    if show_password_var.get():
        result_entry.config(show="")
    else:
        result_entry.config(show="*")

# Main window
root = tk.Tk()
root.title("Advanced Password Generator")
root.geometry("520x350")
root.resizable(False, False)

# Style configuration
style = ttk.Style()
style.configure("TLabel", font=("Helvetica", 12))
style.configure("TButton", font=("Helvetica", 12))
style.configure("TEntry", font=("Helvetica", 12))

# Title
title_label = ttk.Label(root, text="🔐 Advanced Password Generator", font=("Helvetica", 16, "bold"))
title_label.pack(pady=10)

# Frame
main_frame = ttk.Frame(root, padding="10 10 10 10")
main_frame.pack(fill=tk.BOTH, expand=True)

# Password length input
length_label = ttk.Label(main_frame, text="Password Length:")
length_label.grid(row=0, column=0, padx=10, pady=10, sticky="W")
length_entry = ttk.Entry(main_frame)
length_entry.grid(row=0, column=1, padx=10, pady=10, sticky="E")

# Character type options
letters_var = tk.BooleanVar(value=True)
numbers_var = tk.BooleanVar(value=True)
symbols_var = tk.BooleanVar(value=True)

letters_check = ttk.Checkbutton(main_frame, text="Include Letters", variable=letters_var)
letters_check.grid(row=1, column=0, padx=10, pady=5, sticky="W")
numbers_check = ttk.Checkbutton(main_frame, text="Include Numbers", variable=numbers_var)
numbers_check.grid(row=1, column=1, padx=10, pady=5, sticky="W")
symbols_check = ttk.Checkbutton(main_frame, text="Include Symbols", variable=symbols_var)
symbols_check.grid(row=1, column=2, padx=10, pady=5, sticky="W")

# Generate Button
generate_button = ttk.Button(main_frame, text="Generate Password", command=on_generate)
generate_button.grid(row=2, column=0, columnspan=3, pady=10)

# Result
result_label = ttk.Label(main_frame, text="Generated Password:")
result_label.grid(row=3, column=0, padx=10, pady=10, sticky="W")
result_var = tk.StringVar()
result_entry = ttk.Entry(main_frame, textvariable=result_var, state='readonly', show="*")
result_entry.grid(row=3, column=1, columnspan=2, padx=10, pady=10, sticky="WE")

# Show Password toggle
show_password_var = tk.BooleanVar()
show_password_check = ttk.Checkbutton(main_frame, text="Show Password", variable=show_password_var, command=toggle_password_visibility)
show_password_check.grid(row=4, column=0, columnspan=2, padx=10, sticky="W")

# Copy Button
copy_button = ttk.Button(main_frame, text="Copy to Clipboard", command=on_copy)
copy_button.grid(row=5, column=0, columnspan=1, pady=10, padx=10, sticky="W")

# Clear Button
clear_button = ttk.Button(main_frame, text="Clear", command=on_clear)
clear_button.grid(row=5, column=1, columnspan=2, pady=10, padx=10, sticky="E")

# Run the app
root.mainloop()
