import logging
import os
from Crypto.Cipher import AES

class AES128:
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(AES128, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):
        BLOCK_SIZE = 16
        AES_KEY = [ 0x19, 0x17, 0x4e, 0xee, 0x8d, 0x82, 0x83, 0x48, 0xb3, 0x1c, 0x6e, 0x2a, 0xcd, 0xcd, 0x3a, 0x19 ]

        self.cipher = AES.new(bytes(AES_KEY), AES.MODE_ECB)
        self.pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * bytes([BLOCK_SIZE - len(s) % BLOCK_SIZE])

    def get_new_path(self, file_path: str, is_encrypt: bool) -> str:
        dir_name, file_name = os.path.split(file_path)

        if is_encrypt:
            new_name = f'encrypted_{file_name}'
        else:
            new_name = f'decrypted_{file_name}'

        new_path = os.path.join(dir_name, new_name)
        return new_path

    def do_decrypt(self, in_path: str):
        out_path = self.get_new_path(in_path, False)

        try:
            with open(in_path, 'rb') as file:
                file_data = file.read()
                decrypted = self.cipher.decrypt(file_data)

            with open(out_path, 'wb') as file:
                file.write(decrypted)

        except FileNotFoundError:
            logging.error(f"The file at {filepath} was not found.")

        logging.info(f'decrypted done: {out_path}')

    def do_encrypt(self, in_path: str):
        out_path = get_new_path(in_path, True)

        try:
            with open(in_path, 'rb') as file:
                file_data = file.read()
                encrypted = self.cipher.encrypt(self.pad(file_data))

            with open(out_path, "wb") as file:
                file.write(encrypted)

        except FileNotFoundError:
            logging.error(f"The file at {filepath} was not found.")

        logging.info(f'encrypted done: {out_path}')
