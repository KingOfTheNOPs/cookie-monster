import sys
import base64
import sqlite3
import os
from Crypto.Cipher import AES
import binascii
import json
from datetime import datetime, timedelta
from pyasn1.codec.der import decoder

def cookies(key, file_location):
    if os.path.isfile(file_location) == False:
        print("Error: File does not exist")
        sys.exit(1)
    try:
        conn = sqlite3.connect(file_location)
        cursor = conn.cursor()
        cursor.execute('select host_key, "TRUE", path, "FALSE", expires_utc, name, CAST(encrypted_value AS BLOB) from cookies')
        values = cursor.fetchall()
        for host_key, _, path, _, expires_utc, name, encrypted_value in values:
            print("Host: " + host_key)
            print("Path: " + path)
            print("Name: " + name)
            print("Cookie: " + decrypt_data(encrypted_value,key) + ";")
            print("Expires: " + (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)).strftime('%b %d %Y %H:%M:%S'))
            print("")
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def cookies_for_editor(key, file_location):
    cookies = []
    if os.path.isfile(file_location) == False:
        print("Error: File does not exist")
        sys.exit(1)
    try:
        conn = sqlite3.connect(file_location)
        cursor = conn.cursor()
        cursor.execute('select host_key, "TRUE", path, "FALSE", expires_utc, name, CAST(encrypted_value AS BLOB) from cookies')
        values = cursor.fetchall()
        for host_key, _, path, _, expires_utc, name, encrypted_value in values:
            decrypted_value = decrypt_data(encrypted_value, key)
            expiration_date = (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)).timestamp()
            cookie = {
                "domain": host_key,
                "expirationDate": expiration_date,
                "hostOnly": not host_key.startswith('.'),
                "httpOnly": False,
                "name": name,
                "path": path,
                "sameSite": None,
                "secure": False,
                "session": False,
                "storeId": None,
                "value": decrypted_value
            }
            cookies.append(cookie)
        with open('cookies_for_cookie_editor.json', 'w') as f:
            json.dump(cookies, f, indent=4)
        print("Cookies saved to cookies_for_cookie_editor.json")
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def login_data(key, file_location):
    if os.path.isfile(file_location) == False:
        print("Error: File does not exist")
        sys.exit(1)
    try:
        conn = sqlite3.connect(file_location)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
        values = cursor.fetchall()
        for origin_url, username_value, password_value in values:
            print("URL: " + origin_url)
            print("Username: " + username_value)
            print("Password: " + decrypt_data(password_value, key))
            print("")
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def decrypt_data(encrypted_junk, key):
    key = binascii.unhexlify(key)
    version = encrypted_junk[:3]
    if version in (b'v10', b'v11'):
        try:
            nonce = encrypted_junk[3:3 + 12]
            if len(nonce) == 0:
                print("Error: Nonce cannot be empty")
                return ""
            cipher_text = encrypted_junk[3+12:-16]
            tag = encrypted_junk[-16:]
            plain_text = AES.new(key, AES.MODE_GCM, nonce)
            text = plain_text.decrypt(cipher_text)
            return text[32:].decode('utf-8')
        except Exception as e:
            print("Error: Could not decrypt password")
            print(e)
            return ""
    if version in (b'v20'):    
        try:
            nonce = encrypted_junk[3:3 + 12]
            if len(nonce) == 0:
                print("Error: Nonce cannot be empty")
                return ""
            cipher_text = encrypted_junk[3+12:-16]
            tag = encrypted_junk[-16:]
            plain_text = AES.new(key, AES.MODE_GCM, nonce)
            text = plain_text.decrypt(cipher_text)
            return text[32:].decode('utf-8')
        except Exception as e:
            print("Error: Could not decrypt password")
            print(e)
            return ""

def main():
    args = sys.argv[1:]
    if len(args) != 3:
        print("Usage: python decrypt.py <Decrypt Key> [--cookies || --passwords || --cookie-editor <DB File Location>]")
        sys.exit(1)
    key = args[0]
    base64_key = base64.b64encode(key.encode())
    option = args[1]
    file_location = args[2]
    
    key = bytearray(base64.b64decode(base64_key).decode('utf-8').replace('\\x', ''), 'utf-8')
    
    if option == "--cookies":
        cookies(key, file_location)
    elif option == "--passwords":
        login_data(key, file_location)
    elif option == "--cookie-editor":
        cookies_for_editor(key, file_location)
    elif option == "--firefox":
        print("TO DO")
    else:
        print("Usage: python decrypt.py <Decrypt Key> [--cookies || --passwords || --cookie-editor <DB File Location>]")
        sys.exit(1)
    
if __name__ == "__main__":
    main()
