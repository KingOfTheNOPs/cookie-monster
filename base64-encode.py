import sys
import base64

def main():
    args = sys.argv[1:]
    if len(args) != 1:
        print("Usage: python base64-encode.py <key>")
        sys.exit(1)
    key = args[0]
    base64_key = base64.b64encode(key.encode())
    print(base64_key.decode())
    
if __name__ == "__main__":
    main()