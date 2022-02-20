import os
from binascii import hexlify

import logging
import click

from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Hash import SHA256, SHA1
from Crypto.Signature import pss

from poc_asn1 import AuthorizationList, KeyDescription, SecureKeyWrapper, encode_secure_key_wrapper

KM_KEY_FORMAT_RAW = 3

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)


def wrap(wrapping_key_public, plaintext):
    """
    RSA-OAEP key wrapping.

    Args:
        wrapping_key_public: The public key of the RSA wrapping key
        plaintext: The plaintext key to wrap
    """
    rsa_cipher = PKCS1_OAEP.new(
        key=wrapping_key_public, hashAlgo=SHA256, mgfunc=lambda x, y: pss.MGF1(x, y, SHA1))
    return rsa_cipher.encrypt(plaintext)


def encrypt(key, iv, plaintext):
    """
    AES-GCM encryption.

    Args:
        key: The AES encryption key
        iv: The AES initialization vector
        plaintext: The plaintext to encrypt
    """
    aes_cipher = AES.new(key, AES.MODE_GCM, iv)
    return aes_cipher.encrypt_and_digest(plaintext)


def do_server(wrapping_key_public):
    """
    Emulate the remote server in Secure Key Import.

    The server takes the secret key and encrypts it with AES-GCM using ephermeralKey, then
    wraps the encryption key (after xoring it with a mask) with RSA-OAEP and finally
    returns an ASN1 serialization of SecureKeyWrapper.

    See https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry.

    Args:
        wrapping_key_public: The public RSA wrapping key.
    """
    secret = os.urandom(32)
    logging.info(f'secret: {hexlify(secret)}')

    ref_path = 'server-secret-for-reference.bin'
    logging.debug(f'creating {ref_path}')
    with open(ref_path, 'wb') as f:
        f.write(secret)

    # generate IV
    iv = os.urandom(12)
    logging.debug(f'iv: {hexlify(iv)}')

    # generate 256-bit AES encryption key
    ephemeral_key = os.urandom(32)
    logging.debug(f'ephemeral_key: {hexlify(ephemeral_key)}')

    # xor_mask = os.urandom(32)
    xor_mask = b'\x00' * 32
    logging.debug(f'xor_mask: {hexlify(xor_mask)}')

    # xor with mask to get transportKey
    transport_key = bytes([ephemeral_key[i] ^ xor_mask[i] for i in range(32)])
    logging.debug(f'transport_key: {hexlify(transport_key)}')

    logging.debug(f'wrapping the transport key with the public RSA wrapping key')
    encrypted_transport_key = wrap(wrapping_key_public, transport_key)

    logging.debug(f'encrypting the secure secret with the AES ephermeral key')
    encrypted_secret, tag = encrypt(ephemeral_key, iv, secret)

    logging.debug(f'encrypted_secret: {hexlify(encrypted_secret)}')
    logging.debug(f'tag: {hexlify(tag)}')

    authorizationList = AuthorizationList()

    key_description = KeyDescription()
    key_description['keyFormat'] = KM_KEY_FORMAT_RAW
    key_description['keyParams'] = authorizationList

    secure_key_wrapper = SecureKeyWrapper()
    secure_key_wrapper['version'] = 0
    secure_key_wrapper['encryptedTransportKey'] = encrypted_transport_key
    secure_key_wrapper['initializationVector'] = iv
    secure_key_wrapper['keyDescription'] = key_description
    secure_key_wrapper['encryptedKey'] = encrypted_secret
    secure_key_wrapper['tag'] = tag

    encoded_secure_key_wrapper = encode_secure_key_wrapper(secure_key_wrapper)

    return encoded_secure_key_wrapper, xor_mask


@click.command()
@click.argument('recovered-wrapping-key-path')
@click.argument('output-secure-key-wrapper')
@click.argument('output-xor-mask')
def main(recovered_wrapping_key_path, output_secure_key_wrapper, output_xor_mask):
    """
    Usage: python poc_server.py recovered-wrapping_key out mask
    """
    with open(recovered_wrapping_key_path, 'rb') as f:
        recovered_wrapping_key = f.read()
        wrapping_key_private = RSA.importKey(recovered_wrapping_key)
        wrapping_key_public = wrapping_key_private.publickey()
        logging.debug(f'wrapping_key_public.e: {hex(wrapping_key_public.e)}')

    encoded_secure_key_wrapper, xor_mask = do_server(wrapping_key_public)

    logging.debug(f'creating {output_secure_key_wrapper}')
    with open(output_secure_key_wrapper, 'wb') as f:
        f.write(encoded_secure_key_wrapper)

    logging.debug(f'creating {output_xor_mask}')
    with open(output_xor_mask, 'wb') as f:
        f.write(xor_mask)


if __name__ == '__main__':
    main()
