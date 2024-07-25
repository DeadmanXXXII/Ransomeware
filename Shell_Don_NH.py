import base64
import urllib.parse
import html
import json
import argparse
import sys

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
def generate_decoders(command, hex_encoded, base64_encoded, url_encoded, html_encoded, json_encoded, markdown_encoded, binary_encoded, substitution_cipher_encoded, substitution_key):
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

def print_results(command, decoders):
    print("\n==============================")
    print("Shell_Don")
    print("==============================\n")
    
    print(f"Original Command: {command}\n")
    
    print(f"Hexadecimal:\n{decoders['hex']}\n")
    print(f"Base64:\n{decoders['base64']}\n")
    print(f"URL Encoded:\n{decoders['url']}\n")
    print(f"HTML Encoded:\n{decoders['html']}\n")
    print(f"JSON Encoded:\n{decoders['json']}\n")
    print(f"Markdown Encoded:\n{decoders['markdown']}\n")
    print(f"Binary:\n{decoders['binary']}\n")
    print(f"Substitution Cipher:\n{decoders['substitution']}\n")
    
    print("Decoding and Execution Payloads:\n")
    for encoding, decoder in decoders.items():
        print(f"{encoding.capitalize()} Decoder:\n{decoder} | bash\n")
    
    print("==============================")
    print("Built by DeadmanXXXII")
    print("==============================")

def main():
    """Main function for command-line interface."""
    parser = argparse.ArgumentParser(description='Encode and decode shell commands.')
    parser.add_argument('command', help='The shell command to encode.')
    parser.add_argument('substitution_key', type=int, help='The substitution cipher key (0-61).')
    parser.add_argument('--preview', action='store_true', help='Preview the decoding commands without executing them.')
    parser.add_argument('--custom-decoding', type=str, help='Custom decoding command. Overrides default decoding commands.')

    args = parser.parse_args()

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

    decoders = generate_decoders(command, hex_encoded, base64_encoded, url_encoded, html_encoded, json_encoded, markdown_encoded, binary_encoded, substitution_cipher_encoded, substitution_key)

    if args.preview:
        print_results(command, decoders)
        return

    print_results(command, decoders)

if __name__ == "__main__":
    main()