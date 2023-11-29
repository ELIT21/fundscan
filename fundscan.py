import os
import codecs
import hashlib
import base58
import ecdsa
import threading
import requests
import concurrent.futures

def generate_private_key():
    return os.urandom(32).hex()

def private_key_to_wif(private_key_hex: str) -> str:
    extended_key = "80" + private_key_hex
    first_sha256 = hashlib.sha256(codecs.decode(extended_key, 'hex')).hexdigest()
    second_sha256 = hashlib.sha256(codecs.decode(first_sha256, 'hex')).hexdigest()
    final_key = codecs.decode(extended_key + second_sha256[:8], 'hex')
    return base58.b58encode(final_key).decode('utf-8')

def private_key_to_address(private_key_hex: str) -> str:
    sk = ecdsa.SigningKey.from_string(codecs.decode(private_key_hex, 'hex'), curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    public_key = b'\x04' + vk.to_string()
    hash160 = hashlib.new('ripemd160')
    hash160.update(hashlib.sha256(public_key).digest())
    hash160 = hash160.digest()
    return base58.b58encode_check(b"\x00" + hash160).decode('utf-8')

def get_balance(address):
    url = f"https://blockchain.info/address/{address}?format=json"
    response = requests.get(url)
    if response.status_code == 200:
        data = response.json()
        balance_btc = data["final_balance"] / 100000000.0
        return balance_btc
    else:
        return None

num_keys_to_generate = 999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999
num_threads = 1

file_lock = threading.Lock()

def generate_verify_and_save_keys(thread_id, keys_per_thread):
    start_index = thread_id * keys_per_thread
    end_index = (thread_id + 1) * keys_per_thread

    with file_lock:
        with open('verified_addresses.txt', 'a') as verified_file:
            for i in range(start_index, end_index):
                private_key = generate_private_key()
                wif_private_key = private_key_to_wif(private_key)
                bitcoin_address = private_key_to_address(private_key)
                
                # Repeat until balance verification succeeds
                while True:
                    balance = get_balance(bitcoin_address)
                    if balance is not None and balance > 0.00000000:
                        verified_file.write(f"Address: {bitcoin_address}, Balance: {balance} BTC, WIF Private Key: {wif_private_key}\n")
                        print(f"Address verified: {bitcoin_address}, Balance: {balance} BTC, WIF Private Key: {wif_private_key} (by thread {thread_id})")
                        break
                    elif balance is not None:
                        print(f"Address verified: {bitcoin_address}, Insufficient balance: {balance} BTC (by thread {thread_id})")
                        break
                    else:
                        print(f"Unable to verify address: {bitcoin_address} (by thread {thread_id}). Retrying...")
                
keys_per_thread = num_keys_to_generate // num_threads

threads = []
for i in range(num_threads):
    thread = threading.Thread(target=generate_verify_and_save_keys, args=(i, keys_per_thread))
    threads.append(thread)
    thread.start()

for thread in threads:
    thread.join()

print(f"{num_keys_to_generate} WIF Private Key pairs generated, Bitcoin addresses verified with a balance greater than 0.00000000 BTC, and results saved in 'verified_addresses.txt'")