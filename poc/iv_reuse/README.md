# IV Reuse

## Summary

A privileged attacker can extract the plaintext key material from hardware-protected keys that were encrypted in the Secure World by the Keymaster TA (Trusted Application).

The root cause of the vulnerability is the ability of an attacker with sufficient permissions (application context or root and SELinux context) in the Normal World to set the IV that the Keymaster TA in the Secure World uses to encrypt key blobs with AES-GCM, for instance in the `importKey` API. This leads to a possible IV reuse attack on AES-GCM that we've exploited to fully recover the key material of encrypted key blobs.

The attack can lead to catastrophic failure: for instance, any application that uses the [Hardware-backed Keystore](https://source.android.com/security/keystore) relies on the security of the hardware-protected key blobs, and the trust assumption that the plaintext key material never leaves the Secure World (and shouldn't be accessible from the Normal World) is broken.

Affected models included Galaxy S9, J3 Top, J7 Top, J7 Duo, TabS4, Tab-A-S-Lite, A6 Plus, A9S. Later models, including S10, S20, and S21 were vulnerable to a downgrade attack as described in [CVE-2021-25490](../downgrade/README.md), which makes IV reuse possible. Samsung assigned [CVE-2021-25444](https://security.samsungmobile.com/securityUpdate.smsb?year=2021&month=8) with High severity to the issue and released a patch that prevents malicious IV reuse by removing the option to add a custom IV from the API.

## Requirements

Our exploit should work in any process that is able to communicate with the kernel driver that switches to the Secure World, e.g., a system service such as `keystored` (if compromised).

In reality, rooting the device is not necessary. Even without root or a strong context (from a kernel exploit, for instance), an attacker that achieves code execution inside an application can perform the attack (using only the `importKey` API) to compromise hardware-protected keys that the application created and used.

We rooted our device using [Magisk](https://github.com/topjohnwu/Magisk) and used the strong context that it provides to run `keybuster`.

## Overview

The high level overview of the exploit is as follows:

1. Create a key blob `blob_a` encryption version that is `v15`.

    - Let `iv-blob_a.bin` be the IV that was used to encrypt `blob_a` (if not given, it should be random) that is stored in the ekey blob.
    - Let `encrypted-blob_a.bin` be the encrypted serialized key material, that is `(km_ekey_blob *)blob_a->ekey`

2. Create a key blob `blob_b` with known key material using the same application ID, application data and IV that were used to encrypt `blob_a`. This key must be at least as long as the first key in order for us to xor the ciphertexts.

    - We pass `iv-blob_a.bin` (parsed from the ASN1 deserialization of `blob_a.bin`) to the creation of `blob_b` (import/generate) to create the collision
    - Let `encrypted-blob_b.bin` be the encrypted serialized key material, that is `(km_ekey_blob *)blob_b->ekey`
    - Let `plain-blob_b.bin` be the known key material of `blob_b` (the key that we import, or the result of `exportKey` on an exportable symmetric key)

3. Finally, xor `plain-blob_b.bin` with `encrypted-blob_b.bin` and `encrypted-blob_a.bin` to recover the plaintext key material of `blob_a`.

The following image from the paper shows why this works:
![xor.png](/images/xor.png "xor.png")

On Galaxy S9 (and similar devices) the KDF in `v20` blobs is deterministic therefore all key blobs are vulnerable (both `v20` and `v15`).

Overall, we managed to fully recover an unknown key blob that the Keymaster TA encrypted in the TEE.

## Running the PoC

To reproduce the PoC, perform the following steps:

1. Upload `keybuster` to the device (`adb push`) to `/data/local/tmp/`
    - If needed, compile it with `ndk-build -C jni`
2. Upload the PoC scripts ([`poc.sh`](poc.sh), [`poc_rsa.sh`](poc_rsa.sh) and - for the S9 - [`poc_s9.sh`](poc_s9.sh)) and the keys that they use ([`key_1_4096.der`](key_1_4096.der) and [`key_2_4096.der`](key_2_4096.der) for [`poc_rsa.sh`](poc_rsa.sh)) to `/data/local/tmp/`
3. Set executable permissions `chmod +x /data/local/tmp/poc*`
4. Execute the PoC scripts

An example of commands to run on the desktop computer:
```bash
adb push keybuster /data/local/tmp/keybuster  # can compile with `ndk-build -C jni` if needed
adb push poc.sh /data/local/tmp/poc.sh
adb push poc_rsa.sh /data/local/tmp/poc_rsa.sh
adb push key_1_4096.der /data/local/tmp/key_1_4096.der
adb push key_2_4096.der /data/local/tmp/key_2_4096.der
# if the device is S9, run `adb push poc_s9.sh /data/local/tmp/poc_s9.sh`
```

An example of commands to run on the Android device:
```bash
adb shell
su # enter a strong context, e.g. by rooting with Magisk
cd /data/local/tmp
chmod +x poc*
./poc.sh
./poc_rsa.sh
# if the device is S9, run `./poc_s9.sh`
```

An example of the files in `/data/local/tmp` before running the PoC:
```bash
star2lte:/data/local/tmp # ls -la
total 104
drwxrwx--x 2 shell shell  4096 2021-05-23 23:36 .
drwxr-x--x 5 root  root   4096 2021-05-23 23:14 ..
-rw-rw-rw- 1 shell shell  2348 2021-04-27 02:20 key_1_4096.der
-rw-rw-rw- 1 shell shell  2350 2021-04-27 02:20 key_2_4096.der
-rw-rw-rw- 1 shell shell 56816 2021-05-22 18:01 keybuster
-rwxrwxrwx 1 shell shell  5006 2021-05-22 17:49 poc.sh
-rwxrwxrwx 1 shell shell  4713 2021-05-22 17:49 poc_rsa.sh
-rwxrwxrwx 1 shell shell  4807 2021-05-22 17:49 poc_s9.sh
```

An example of the files in `/data/local/tmp` after running the PoC scripts ([`poc.sh`](poc.sh), [`poc_rsa.sh`](poc_rsa.sh) and [`poc_s9.sh`](poc_s9.sh)):

```bash
star2lte:/data/local/tmp # ls -la
total 180
drwxrwx--x 2 shell shell  4096 2021-05-23 23:37 .
drwxr-x--x 5 root  root   4096 2021-05-23 23:14 ..
-rw-r--r-- 1 root  root     32 2021-05-23 23:36 aes_256_key.bin
-rw-r--r-- 1 root  root  34600 2021-05-23 23:37 attack.log
-rw-r--r-- 1 root  root   2632 2021-05-23 23:37 blob_a.bin
-rw-r--r-- 1 root  root   2659 2021-05-23 23:37 blob_b.bin
-rw-r--r-- 1 root  root   2567 2021-05-23 23:37 encrypted-blob_a.bin
-rw-r--r-- 1 root  root   2594 2021-05-23 23:37 encrypted-blob_b.bin
-rw-r--r-- 1 root  root     12 2021-05-23 23:37 iv-blob_a.bin
-rw-r--r-- 1 root  root     12 2021-05-23 23:37 iv-blob_b.bin
-rw-rw-rw- 1 shell shell  2348 2021-04-27 02:20 key_1_4096.der
-rw-rw-rw- 1 shell shell  2350 2021-04-27 02:20 key_2_4096.der
-rwxrwxrwx 1 shell shell 56816 2021-05-22 18:01 keybuster
-rw-r--r-- 1 root  root   2350 2021-05-23 23:37 plain-blob_b.bin
-rwxrwxrwx 1 shell shell  5006 2021-05-22 17:49 poc.sh
-rwxrwxrwx 1 shell shell  4713 2021-05-22 17:49 poc_rsa.sh
-rwxrwxrwx 1 shell shell  4807 2021-05-22 17:49 poc_s9.sh
-rw-r--r-- 1 root  root   2350 2021-05-23 23:37 recovered-blob_a.bin
-rw-r--r-- 1 root  root   2348 2021-05-23 23:37 truncated-recovered-blob_a.bin
```

## Notes

Note that `blob_a` can be unknown, and we can verify the correctness of the recovered key by performing a cryptographic operation (e.g. sign/encrypt) - instead, the PoC uses a known key to show that the attack recovers it correctly.

For an example of recovering RSA keys, see [`poc_rsa.sh`](poc_rsa.sh). To see the same attack on S9, which works on `v20` blobs as well, see [`poc_s9.sh`](poc_s9.sh).

`key_1_4096.der` and `key_2_4096.der` are DER files for RSA keys that [`poc_rsa.sh`](poc_rsa.sh) uses as an example (input to `importKey`).

Note that the second key that we import (in order to recover the other key) has to be longer than the recovered key. In our example ([`poc_rsa.sh`](poc_rsa.sh)), the DER of the second key is longer, so we get extra bytes at the end of the recovered DER which we can truncate in order to get the full key material.

The following image shows a successful run of [`poc.sh`](poc.sh) on a Galaxy S10:
![poc.png](/images/poc.png "poc.png")

The following image shows a successful run of [`poc_s9.sh`](poc_s9.sh) on a Galaxy S9:
![poc_s9.png](/images/poc_s9.png "poc_s9.png")

The following image shows a successful run of [`poc_rsa.sh`](poc_rsa.sh) on a Galaxy S21:
![poc_rsa.png](/images/poc_rsa.png "poc_rsa.png")
