import base64
import urllib.parse
import html
import json
import zlib
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import scrolledtext, messagebox
import argparse

# Encoding functions
def to_hex(command):
    return ''.join(format(ord(c), '02x') for c in command)

def to_base64(command):
    return base64.b64encode(command.encode('utf-8')).decode('utf-8')

def to_url_encode(command):
    return urllib.parse.quote(command)

def to_html_encode(command):
    return html.escape(command)

def to_json_encode(command):
    return json.dumps(command)

def to_markdown_encode(command):
    return f"```\n{command}\n```"

def to_binary(command):
    return ' '.join(format(ord(c), '08b') for c in command)

def to_substitution_cipher(command, key):
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    shifted_alphabet = alphabet[key:] + alphabet[:key]
    table = str.maketrans(alphabet, shifted_alphabet)
    return command.translate(table)

# Decoding functions
def generate_decoders(command, hex_encoded, base64_encoded, url_encoded, html_encoded, json_encoded, markdown_encoded, binary_encoded, substitution_cipher_encoded, substitution_key, custom_decoding=None):
    decoders = {}

    # Hexadecimal decoder
    decoders['hex'] = f"echo {hex_encoded} | xxd -r -p"

    # Base64 decoder
    decoders['base64'] = f"echo {base64_encoded} | base64 -d"

    # URL decoder
    decoders['url'] = f"echo {url_encoded} | python3 -c 'import urllib.parse, sys; print(urllib.parse.unquote(sys.stdin.read()))'"

    # HTML decoder
    decoders['html'] = f"echo {html_encoded} | python3 -c 'import html, sys; print(html.unescape(sys.stdin.read()))'"

    # JSON decoder
    decoders['json'] = f"echo {json_encoded} | python3 -c 'import json, sys; print(json.loads(sys.stdin.read()))'"

    # Markdown decoder
    decoders['markdown'] = f"echo {markdown_encoded} | python3 -c 'import sys; print(sys.stdin.read().strip().strip(\"```\"))'"

    # Binary decoder
    binary_script = f"""
binary="{binary_encoded}"
echo $binary | perl -lpe '$_=pack"B*",$_'
"""
    decoders['binary'] = binary_script

    # Substitution cipher decoder
    alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    shifted_alphabet = alphabet[-substitution_key:] + alphabet[:-substitution_key]
    decoders['substitution'] = f"echo {substitution_cipher_encoded} | tr '{shifted_alphabet}' '{alphabet}'"

    return decoders

# GUI Functions
def generate_output(command, substitution_key):
    hex_encoded = to_hex(command)
    base64_encoded = to_base64(command)
    url_encoded = to_url_encode(command)
    html_encoded = to_html_encode(command)
    json_encoded = to_json_encode(command)
    markdown_encoded = to_markdown_encode(command)
    binary_encoded = to_binary(command)
    substitution_cipher_encoded = to_substitution_cipher(command, substitution_key)

    decoders = generate_decoders(command, hex_encoded, base64_encoded, url_encoded, html_encoded, json_encoded, markdown_encoded, binary_encoded, substitution_cipher_encoded, substitution_key)
    
    # Build the display content
    output = f"Original Command: {command}\n\n"
    output += f"Hexadecimal: {hex_encoded}\n"
    output += f"Base64: {base64_encoded}\n"
    output += f"URL Encoded: {url_encoded}\n"
    output += f"HTML Encoded: {html_encoded}\n"
    output += f"JSON Encoded: {json_encoded}\n"
    output += f"Markdown Encoded: {markdown_encoded}\n"
    output += f"Binary: {binary_encoded}\n"
    output += f"Substitution Cipher: {substitution_cipher_encoded}\n\n"
    
    output += "Decoding and Execution Payloads:\n"
    for encoding, decoder in decoders.items():
        output += f"{encoding.capitalize()} Decoder:\n{decoder} | bash\n\n"
    
    return output

def show_gui():
    def on_generate():
        command = entry_command.get("1.0", tk.END).strip()
        try:
            substitution_key = int(entry_key.get())
            if not (0 <= substitution_key <= 61):
                raise ValueError("Substitution key must be between 0 and 61.")
            output = generate_output(command, substitution_key)
            text_output.config(state=tk.NORMAL)
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, output)
            text_output.config(state=tk.DISABLED)
        except ValueError as e:
            messagebox.showerror("Input Error", str(e))

    root = tk.Tk()
    root.title("Command Encoder/Decoder")

    # Input Frame
    frame_input = tk.Frame(root)
    frame_input.pack(padx=10, pady=10)

    tk.Label(frame_input, text="Shell Command:").grid(row=0, column=0, sticky="e")
    entry_command = tk.Text(frame_input, height=5, width=50)
    entry_command.grid(row=0, column=1, padx=5, pady=5)

    tk.Label(frame_input, text="Substitution Key (0-61):").grid(row=1, column=0, sticky="e")
    entry_key = tk.Entry(frame_input, width=10)
    entry_key.grid(row=1, column=1, padx=5, pady=5)

    tk.Button(frame_input, text="Generate", command=on_generate).grid(row=2, column=1, pady=10)

    # Output Frame
    frame_output = tk.Frame(root)
    frame_output.pack(padx=10, pady=10)

    tk.Label(frame_output, text="Output:").pack(anchor="w")
    text_output = scrolledtext.ScrolledText(frame_output, height=20, width=80, wrap=tk.WORD, state=tk.DISABLED)
    text_output.pack()

    root.mainloop()

def main():
    """Main function for command-line interface."""
    parser = argparse.ArgumentParser(description='Encode and decode shell commands.')
    parser.add_argument('command', help='The shell command to encode.')
    parser.add_argument('substitution_key', type=int, help='The substitution cipher key (0-61).')
    parser.add_argument('--preview', action='store_true', help='Preview the decoding commands without executing them.')
    parser.add_argument('--custom-decoding', type=str, help='Custom decoding command. Overrides default decoding commands.')
    parser.add_argument('--gui', action='store_true', help='Launch the GUI for encoding and decoding commands.')

    args = parser.parse_args()

    if args.gui:
        show_gui()
        return

    if not (0 <= args.substitution_key <= 61):
        print("Error: Substitution key must be between 0 and 61.")
        return

    command = args.command
    substitution_key = args.substitution_key
    
    hex_encoded = to_hex(command)
    base64_encoded = to_base64(command)
    url_encoded = to_url_encode(command)
    html_encoded = to_html_encode(command)
    json_encoded = to_json_encode(command)
    markdown_encoded = to_markdown_encode(command)
    binary_encoded = to_binary(command)
    substitution_cipher_encoded = to_substitution_cipher(command, substitution_key)
    
    decoders = generate_decoders(command, hex_encoded, base64_encoded, url_encoded, html_encoded, json_encoded, markdown_encoded, binary_encoded, substitution_cipher_encoded, substitution_key, args.custom_decoding)
    
    if args.preview:
        preview_decoders(decoders)
        return

    print("\nEncoded Shell Command Formats:\n")
    print(f"Original Command: {command}")
    print(f"Hexadecimal: {hex_encoded}")
    print(f"Base64: {base64_encoded}")
    print(f"URL Encoded: {url_encoded}")
    print(f"HTML Encoded: {html_encoded}")
    print(f"JSON Encoded: {json_encoded}")
    print(f"Markdown Encoded: {markdown_encoded}")
    print(f"Binary: {binary_encoded}")
    print(f"Substitution Cipher: {substitution_cipher_encoded}")
    
    print("\nDecoding and Execution Payloads:\n")
    for encoding, decoder in decoders.items():
        # If a custom decoding command is provided, override the default decoder
        if args.custom_decoding:
            decoder = args.custom_decoding
        print(f"{encoding.capitalize()} Decoder:\n{decoder} | bash\n")

if __name__ == "__main__":
    main()