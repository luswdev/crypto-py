import argparse
import logging

from crypto import aes128

if __name__ == '__main__':
    logging.basicConfig(
        format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        level  = logging.INFO,
    )

    parser = argparse.ArgumentParser(description="aes128 sample tool", formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('file', help='target file')

    group = parser.add_argument_group('operation mode', 'set encrypt/decrypt mode')
    mode_group = group.add_mutually_exclusive_group(required=False)
    mode_group.add_argument('-e', '--encrypt', action='store_true', default=False,  help='encrypt mode')
    mode_group.add_argument('-d', '--decrypt', action='store_true', default=True,   help='decrypt mode')

    args = parser.parse_args()

    cipher = aes128.AES128()

    if args.encrypt:
        cipher.do_encrypt(args.file)
    else:
        cipher.do_decrypt(args.file)
