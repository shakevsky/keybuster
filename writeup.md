# Writeup

Our extended paper describes our research on the cryptographic design and implementation of Android's Hardware-Backed Keystore in Samsung's Galaxy devices. This documents extends the paper by providing technical details that help understand our research.

As Kinibi and QSEE have been more thoroughly studied by the security community (e.g. by [Quarkslab](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html) and by [Beniamini](http://bits-please.blogspot.com/2016/05/qsee-privilege-escalation-vulnerability.html)), when we discuss details we refer to TEEGRIS unless otherwise noted.

This document borrows some text from the appendix of the extended paper.


## Table of Contents

- [TL;DR](#tldr)
- [Background](#background) 
    - [Keymaster TA Motivation](#keymaster-ta-motivation)
    - [ARM TrustZone Overview](#arm-trustzone-overview)
    - [Trusted Applications](#trusted-applications)
    - [TEE Client API](#tee-client-api)
- [Firmware Analysis](#firmware-analysis)
    - [Summary](#summary)
    - [First Steps](#first-steps)
- [Reverse Engineering the Keymaster TA](#reverse-engineering-the-keymaster-ta)
    - [Keymaster HAL API Overview](#keymaster-hal-api-overview)
    - [Keymaster HAL Internals](#keymaster-hal-internals)
    - [Keymaster Helper Library](#keymaster-helper-library)
    - [Vendor-specific ASN.1 structures](#vendor-specific-asn1-structures)
    - [Keymaster TA Control Flow](#keymaster-ta-control-flow)
    - [Keymaster TA and HAL in TEEGRIS vs QSEE vs Kinibi](#keymaster-ta-and-hal-in-teegris-vs-qsee-vs-kinibi)
    - [Encryption/Decryption of key blobs](#encryptiondecryption-of-key-blobs)
- [Exploiting the Keymaster TA](#exploiting-the-keymaster-ta)
    - [IV Reuse](#iv-reuse)
    - [Downgrade Attack](#downgrade-attack)
    - [Persistence of `v15` key blobs](#persistence-of-`v15`-key-blobs) 
    - [Bonus: Export of raw symmetric key material](#bonus-export-of-raw-symmetric-key-material)

## TL;DR

In this work, we expose the cryptographic design and implementation of Android's Hardware-Backed Keystore in Samsung's Galaxy S8, S9, S10, S20, and S21 flagship devices. 
We reversed-engineered and provide a detailed description of the cryptographic design and code structure, and we unveil severe design flaws. 

We present an [IV reuse](/poc/iv_reuse/README.md) attack on AES-GCM
that allows an attacker to extract hardware-protected  key material, and a [downgrade attack](/poc/downgrade/README.md) that makes even the latest Samsung devices vulnerable to the IV reuse attack.

For the full details and proof-of-concept attacks, see the README of each attack. In the remainder of this document, we describe technical details that supplement our paper.


## Background

For the full introduction and background please see the paper.

### Keymaster TA Motivation

Android's [Hardware-Backed Keystore](https://source.android.com/security/keystore) uses secure software that runs in the TEE to handle cryptographic operations. Per the documentation:

>Keymaster TA (trusted application) is the software running in a secure context, most often in TrustZone on an ARM SoC, that provides all of the secure Keystore operations, has access to the raw key material, validates all of the access control conditions on keys, etc.


### ARM TrustZone Overview

ARM provides a reference implementation of secure world software called [ARM Trusted Firmware](https://github.com/ARM-software/arm-trusted-firmware) (ATF), and the Secure World is usually implemented by a specific vendor (e.g., Qualcomm, Trustonic, Samsung) based on ATF. ATF is [responsible for](https://chromium.googlesource.com/external/github.com/ARM-software/arm-trusted-firmware/+/v0.4-rc1/docs/firmware-design.md) performing Secure Boot, loading the different bootloaders and launching the REE and TEE. It also contains a reference implementation for a Secure Monitor.

To achieve the isolation of the TEE and the REE, TrustZone uses the NS (Non-Secure) bit which is set to 0 if the processor is in Secure state and set to 1 if the processor is in Non-Secure state. The secure state can be switched by executing the SMC opcode (in exception level higher than EL0, e.g., EL1).

The Secure state applies to hardware peripherals and memory, by using the TZASC register (allows to restrict memory to Secure World only) and the TrustZone Protection Controller (TZPC). [Menarini](https://www.riscure.com/blog/samsung-investigation-part1) shows an example of how the Trusted User Interface (TUI) uses the TZPC to modify the display and touch controllers as secure and the TZASC configures secure memory for the display. Thus, a user can enter a pin for a payment which will be safe from any Normal World attacker (even if the attacker executes code in the Android OS kernel) and will not be leaked.

The Normal World can only access Non-secure memory, but the Secure World can access Non-Secure memory. The ARM [documentation](https://developer.arm.com/documentation/100935/0100/The-TrustZone-hardware-architecture-) states that Secure and Non-secure cache entries can coexist, and that the Normal World can only get a cache hit on Non-secure cache lines.

The ARMv8-A processor supports 4 [exception levels](https://developer.arm.com/documentation/102412/0100/Privilege-and-Exception-levels):

- EL0 - usermode (application in Android, TA in TZOS)
- EL1 - kernelmode (Android kernel, TZOS kernel)
- EL2 - hypervisor (used by Samsung to implement [RKP](https://www.samsungknox.com/en/blog/real-time-kernel-protection-rkp), which protects the integrity of the Android kernel)
- EL3 - Secure Monitor

The following figure[^1] shows the components in each exception level in the TrustZone architecture:

![trustzone_hw.png](/images/trustzone_hw.png "trustzone_hw.png")

When the processor is in Secure mode, we can denote S-ELx, e.g., S-EL0 is the secure EL0. Most of our research focuses on S-EL0 (where the Keymaster TA executes), S-EL1 (where the TZOS kernel handles ioctls that the Keymaster TA calls) and EL3 (where the Secure Monitor executes a function handler for a given SMC).

The Secure Monitor provides the interface between the two worlds and performs switching when the SMC (Secure Monitor Call) opcode is executed. Per the ARM [SMC Calling Convention](https://developer.arm.com/documentation/den0028/latest):

>The SMC instruction is used to generate a synchronous exception that is handled by Secure Monitor code running in EL3. The arguments are passed in registers and then used to select which Secure function to execute. These calls may then be passed on to a Trusted OS in S-EL1.

Note that the Secure World also uses SMC for some operations, such as power management or privileged operations that can only be done in the Secure Monitor (EL3).

### Trusted Applications

A Trusted Application (TA) is a program that runs in the TEE and exposes security services to Android client applications.

The application can open a session with the TA and invoke commands within the session. After receiving a command, a TA parses the commands input, performs required processing and sends a response back to the client. Control is transferred to the TA via the dedicated SMC (Secure Monitor Call) instruction, and the TA and Normal World application usually exchange arguments and output using a shared memory buffer called World Shared Memory.

As performing SMCs requires EL1 privileges, a device driver in the Android kernel handles the communication with the TA and exposes an API for Normal World applications.

### TEE Client API

Client Applications in the Normal World can communicate with Trusted Applications (TAs) using World Shared Memory buffers and SMCs.

In TEEGRIS, Samsung followed the GlobalPlatform TEE [specification](https://globalplatform.org/wp-content/uploads/2016/11/GPD_TEE_Internal_Core_API_Specification_v1.2_PublicRelease.pdf) that defines a set of C APIs for the development of TA running inside a TEE.

In most cases, a Client Application calls a client API function such as `TEEC_OpenSession` in the Normal World (EL0), which triggers an SMC opcode in the Normal World kernel (EL1) and execution switches to the Secure Monitor, who will switch execution to the Secure World TZOS kernel (S-EL1) that will schedule the TA and call the appropriate TA API function such as `TA_CreateEntryPoint`, and will return the response to the client. The common API functions are:
 
- `TA_CreateEntryPoint`: Constructor
- `TA_OpenSessionEntryPoint`: Called when a client opens a session with `TEEC_OpenSession`
- `TA_InvokeCommandEntryPoint`: Called when a client calls `TEEC_InvokeCommand`.
- `TA_CloseSessionEntryPoint`: Called when a client closes a session with `TEEC_CloseSession`
- `TA_DestroyEntryPoint`: Destructor


## Firmware Analysis

### Summary
The firmware of the device contains a binary called `sboot.bin` that is Samsung's implementation of Secure Boot for Exynos models based on ATF. 

Based on our reverse engineering using [Ghidra](https://github.com/NationalSecurityAgency/ghidra) and on previous work by [Quarkslab](https://blog.quarkslab.com/reverse-engineering-samsung-s6-sboot-part-i.html) on SBOOT in Galaxy S6 devices with Kinibi as the TZOS, as well as useful information by [Tarasikov](https://allsoftwaresucks.blogspot.com/2019/05/reverse-engineering-samsung-exynos-9820.html) about reverse engineering SBOOT in Galaxy S10 devices, we extracted BL2 (the second stage bootloader) and the TEEGRIS OS binary from SBOOT. Both SBOOT and TEEGRIS are 64 bit binaries in a proprietary format.

Images of TAs were found in `vendor/tee` and `system/tee`, while `root_task` (a task in TEEGRIS that is similar to `init` in Linux and is responsible to spawn TAs) and important libraries were found in `startup.tzar` (and were extracted by the following [script](https://gist.github.com/astarasikov/f47cb7f46b5193872f376fa0ea842e4b)). We mostly reversed 32 bit TAs (mainly the Keymaster TA) and libraries which are ELF files with a special header and footer, therefore by stripping the headers we were able to reverse them easily - especially as most functions have debug strings (usually with the name of the function and other useful information). Important files include:

- `00000000-0000-0000-0000-4b45594d5354`: the Keymaster TA (in `vendor/tee`)
- `libteesl.so`: TEE API for TAs
- `libscrypto.so`: Samsung [SCrypto](https://csrc.nist.gov/CSRC/media/projects/cryptographic-module-validation-program/documents/security-policies/140sp3027.pdf) Cryptographic Module, which seems to be a modification of [BoringSSL](https://boringssl.googlesource.com/boringssl/)
- `libtzsl.so`: Includes wrappers to TEEGRIS syscalls

The main object of interest in our research was not TEEGRIS itself but the crypto driver (`dev://crypto`) that wraps and unwraps hardware-protected keys.

### First steps

To begin our exploration we've used the following steps:

1. Download (e.g., from [SamMobile](https://www.sammobile.com)) the firmware of the specific model (e.g., Samsung Galaxy S10 G973F)  
2. Extract `system.img`, `vendor.img` and `sboot.bin` (includes TEEGRIS)
    - Use [`simg2img`](https://github.com/anestisb/android-simg2img) to convert the system/vendor images to ext4 images and extract using `testdisk` or `mount`
    - Use `lz4` to extract archives
3. Download the [open source archive](https://opensource.samsung.com/uploadList?menuItem=mobile&classification1=mobile_phone) for the specific model and extract `startup.tzar`
    - Use a [script by Tarasikov](https://gist.github.com/astarasikov/f47cb7f46b5193872f376fa0ea842e4b) to unpack files in `startup.tzar`
4. Read public documentation and security certifications
5. Reverse engineer using Ghidra
    - Keymaster TA and libraries that it uses
    - Keymaster HAL libraries
    - `sboot.bin` for TEEGRIS
    - The open-source kernel drivers can be used for reference


## Reverse Engineering the Keymaster TA

### Keymaster HAL API Overview

The Keymaster HAL API is a set of shared-objects that implement the required API for sending and receiving requests to the Keymaster TA using kernel drivers, as well as creating and using world-shared memory buffers.

- Normal World usermode applications can request (using a binder API) cryptographic operations from system applications.
- Normal world usermode system applications, such as `keystored` and `vold`, can use the Keymaster HAL API.
- Normal World kernel drivers, such as `tzdaemon`, handle requests from Normal World and can perform a SMC to communicate with TEEGRIS and a particular TA.
- The Secure Monitor handles SMCs from Normal World and forwards the request to the Secure World OS (TEEGRIS).
- The Secure World kernel handles requests from the Secure Monitor and prepares the Keymaster TA.
- The Keymaster TA in the Secure World usermode handles input from Normal World and returns output to World Shared buffers.

The following figure[^1] illustrates the flow:

![teegris_keymaster_api.png](/images/teegris_keymaster_api.png "teegris_keymaster_api.png")

### Keymaster HAL Internals

The Keymaster HAL is made up of several components in the Android usermode:

- `SKeymaster4Device`: Samsung's implementation of [`AndroidKeymaster4Device`](https://android.googlesource.com/platform/system/keymaster/+/refs/heads/master/ng/AndroidKeymaster4Device.cpp) (a C++ class that implements Keymaster functions by calling API from C libraries). Implemented in `libkeymaster4device.so`.
- Wrapper libraries that expose Keymaster API, such as `libkeymaster4.so`
- `android.hardware.keymaster@4.0-service`: exposes API to construct requests in the vendor-specific format for the Keymaster TA.

Most of our focus was on `libkeymaster_helper.so` which the HAL uses.

The Keymaster HAL is registered as a service by the Keymaster [HIDL](https://source.android.com/devices/architecture/hidl):

```c
IKeymasterDevice* keymaster = 
skeymaster::CreateSKeymasterDevice(
SecurityLevel::TRUSTED_ENVIRONMENT);
// ...
status_t status = keymaster->registerAsService();
// ...
LOG(INFO) << "Keymaster HAL service is Ready.";
```

The `CreateKeymasterDevice` function creates an object of `SKeymaster4Device` and calls the `waitKeymaster_` method which opens a session to the Keymaster TA and runs the `configure` command. Later, Android services such as `keystored` will call specific Keymaster functions (e.g., `generateKey`) that the device object implements - most will use library functions to construct the appropriate requests in the vendor-specific format and use the GlobalPlatform Client API that `libteecl.so` implements to send it to the Keymaster TA.

### Keymaster Helper Library

The Keymaster HAL uses `libkeymaster_helper.so` to communicate with the Keymaster TA using a TZOS-specific API. By calling it directly we can provide arbitrary parameters to the Keymaster TA and expand the attack surface. By patching it or recreating it we can bypass all usermode input validation (e.g., hash check of key blobs).

The `libkeymaster_helper.so` exports the following functions:

```c
KM_Result nwd_open_connection(void);
KM_Result nwd_close_connection(void);

KM_Result nwd_configure(keymaster_key_param_set_t *param_set);

KM_Result nwd_generate_key(
    keymaster_key_param_set_t *param_set,
    vector_t *ekey,
    keymaster_key_characteristics_t *characteristics);

KM_Result nwd_get_key_characteristics(
    vector_t *ekey,
    vector_t *application_id,
    vector_t *application_data,
    keymaster_key_characteristics_t * characteristics);

KM_Result nwd_import_key(
    keymaster_key_param_set_t *param_set,
    long key_format,
    vector_t *key_data,
    vector_t *ekey,
    keymaster_key_characteristics_t *characteristics);

KM_Result nwd_export_key(
    long key_format,
    vector_t *ekey,
    vector_t *application_id,
    vector_t *application_data,
    vector_t *exported);

KM_Result nwd_upgrade_key(
    vector_t *ekey,
    keymaster_key_param_set_t *param_set,
    vector_t *new_ekey);

KM_Result nwd_begin(
    keymaster_key_param_set_t *param_set,
    long purpose,
    vector_t *ekey,
    int64_t *operation_handle,
    keymaster_key_param_set_t *out_params);

KM_Result nwd_finish(
    keymaster_key_param_set_t *param_set,
    vector_t *data,
    vector_t *signature,
    int64_t *operation_handle,
    vector_t *output,
    keymaster_key_param_set_t *output_params);
```

Internaly, the following functions are used:

- `nwd_tz_open`: Read the TA file and initialize a Keymaster TA context using a TZOS-specific API (e.g., in TEEGRIS it calls `TEEC_InitializeContext`, `TEECS_OpenSession`, and `TEEC_RegisterSharedMemory`).
- `nwd_km_KM_INDATA_pack`: Prepares the vendor-specific format `km_indata_t` ASN.1, writes it to World Shared memory buffers,  and calls `nwd_tz_run_cmd`.
- `nwd_tz_run_cmd`: Invokes a command in the Keymaster TA using a TZOS-specific API (e.g., in TEEGRIS it calls `TEEC_InvokeCommand` per the GlobalPlatform Client API, and in Kinibi it uses `mcNotify` and `mcWaitNotification`).
- `nwd_KM_OUTDATA_unpack`: Parse the vendor-specific format `km_outdata_t` ASN.1 from the World Shared memory buffers.

For our research it's enough to call `nwd_import_key` directly (and pass custom parameters), but it can be useful to patch or re-implement the internal functions (e.g., pass the input checks in `nwd_km_KM_INDATA_pack`).

### Vendor-specific ASN.1 structures

The Keymaster TA and Keymaster HAL Normal World libraries communicate using the following formats:

```c
// input from Keymaster HAL to Keymaster TA
typedef struct km_indata_t {
    ASN1_INTEGER *ver;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *km_ver;                                   // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_INTEGER *cmd;                                      // offset: 0x08, flags: 0x00, tag: 0x00
    ASN1_INTEGER *pid;                                      // offset: 0x0c, flags: 0x00, tag: 0x00
    ASN1_INTEGER *int0;                                     // offset: 0x10, flags: 0x91, tag: 0x00
    ASN1_INTEGER *long0;                                    // offset: 0x14, flags: 0x91, tag: 0x01
    ASN1_INTEGER *long1;                                    // offset: 0x18, flags: 0x91, tag: 0x02
    ASN1_OCTET_STRING *bin0;                                // offset: 0x1c, flags: 0x91, tag: 0x03
    ASN1_OCTET_STRING *bin1;                                // offset: 0x20, flags: 0x91, tag: 0x04
    ASN1_OCTET_STRING *bin2;                                // offset: 0x24, flags: 0x91, tag: 0x05
    ASN1_OCTET_STRING *key;                                 // offset: 0x28, flags: 0x91, tag: 0x06
    km_param_t *par;                                        // offset: 0x2c, flags: 0x93, tag: 0x08
    int flags;
} km_indata_t;

// Output from Keymaster TA to Keymaster HAL
typedef struct km_outdata_t {
    ASN1_INTEGER *ver;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *cmd;                                      // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_INTEGER *pid;                                      // offset: 0x08, flags: 0x00, tag: 0x00
    ASN1_INTEGER *err;                                      // offset: 0x0c, flags: 0x00, tag: 0x00
    ASN1_INTEGER *int0;                                     // offset: 0x10, flags: 0x91, tag: 0x00
    ASN1_INTEGER *long0;                                    // offset: 0x14, flags: 0x91, tag: 0x01
    ASN1_OCTET_STRING *bin0;                                // offset: 0x18, flags: 0x91, tag: 0x02
    ASN1_OCTET_STRING *bin1;                                // offset: 0x1c, flags: 0x91, tag: 0x03
    ASN1_OCTET_STRING *bin2;                                // offset: 0x20, flags: 0x91, tag: 0x04
    ASN1_OCTET_STRING *log;                                 // offset: 0x24, flags: 0x91, tag: 0x05
    int flags;
} km_outdata_t;
```

#### Key blob structure


The Keymaster TA uses ASN.1 to serialize keys as follows:

- The key material is serialized into an ASN.1 structure called `km_key_blob_t` that contains a version number, key material and key parameters (`km_param_t`).
- The ASN.1 structure is then encrypted using AES-256-GCM with an Hardware Derived Key-encryption-key (HDK). This encryption is called "wrapping" and is the topic of much of our work.
- The "wrapped" key blob is serialized again into another ASN.1 structure called `km_ekey_blob_t` that contains information that is required for decryption, such as the IV and AAD that was used to encrypt.

The following ASN.1 structures are used:
```c
// key parameters
typedef struct km_param_t {
    ASN1_INTEGER *tag;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_INTEGER *i;                                        // offset: 0x04, flags: 0x91, tag: 0x00
    ASN1_OCTET_STRING *b;                                   // offset: 0x08, flags: 0x91, tag: 0x01
    int flags;                                              // offset: 0x10
} km_param_t;

// key material and key parameters
typedef struct km_key_blob_t {
    ASN1_INTEGER *ver;                                      // offset: 0x00, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *key;                                 // offset: 0x04, flags: 0x00, tag: 0x00
    km_param_t *par;                                        // offset: 0x08, flags: 0x93, tag: 0x00
} km_key_blob_t;

// encrypted key blob and encryption parameters
typedef struct km_ekey_blob_t {
    km_key_blob_t *key_blob;
    ASN1_INTEGER *enc_ver;                                  // offset: 0x04, flags: 0x00, tag: 0x00
    ASN1_OCTET_STRING *ekey;                                // offset: 0x08, flags: 0x00, tag: 0x00
    km_param_t *enc_par;                                    // offset: 0x0c, flags: 0x02, tag: 0x00
} km_ekey_blob_t;
```

See [`skeymaster_asn1.h`](jni/core/skeymaster_asn1.h) for more details.

##### Example of ekey blob

```
   SEQUENCE {
      INTEGER 0x0F (15 decimal)
      OCTETSTRING FBDA5965263CB66E9B378CD32A3E498BB26AD9A6F70105A16C7EE3AE09ACCDDC2CB9D4C70A35EEE3225872DE0BA4165A644B45279A6F8BD97E505002049951AA9A0E4A29A215452295AE5E1CD5330A9A8E2837019DB09EBABEDA12AF92F648185CB8F1C9AD76AF609471815DA1FA280845ECB6CD10CFB18AABC58087045B4B7CE5D863099799BCA26EA27D54C4A48E675977F7A3DC9DC94D41D17EAFDC17B7800821444FB17549741737DF7C09D5473581736FA4DD45600DFBFF9B94242C00A738788E5EDDFD62F7909DD1B5DFE50755BDDDFA993FE5DE2728C4AF8A3506B592DE19FF4CA8F583B8C941EDE6DE2537C604401E497411055BF3AAB4B01EBF941FFC1DE5B5C4DCD23B75BBC62F5214B783B0FCE8EABD4217773ED81589C251BDB8670E5F658017472F4C5B1774C559149C9D760AA5A80D2954C29BA4A853FB02A5DFADA107A1884352898AD854D6A29EFE6EC4B640B5740DDDF4C79620528C91BBDFF63469EFC436062EE0F41B00C8AE2DDD576CF50666
      SET {
         SEQUENCE {
            INTEGER 0x90001388
            [1] {
               OCTETSTRING 784D473DD1C619981FFFDCF8
            }
         }
         SEQUENCE {
            INTEGER 0x90001389
            [1] {
               OCTETSTRING 0619443C086011B2263D3D35FA823FD8
            }
         }
         SEQUENCE {
            INTEGER 0x90001392
            [1] {
               OCTETSTRING 476DA2F2613A18C2F034EE4672AA2D58
            }
         }
      }
   }
```

##### Example of key blob

```
   SEQUENCE {
      INTEGER 0x02 (2 decimal)
      OCTETSTRING 6CB9E19A1A1DD01113FDD2160E2485509DACC4A799A61C7EE70323A3E35F29C6
      [0] {
         SET {
            SEQUENCE {
               INTEGER 0x10000002 (268435458 decimal)
               [0] {
                  INTEGER 0x20 (32 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x20000004 (536870916 decimal)
               [0] {
                  INTEGER 0x20 (32 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x30001390 (805311376 decimal)
               [0] {
                  INTEGER 0x0F (15 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x700001F7 (1879048695 decimal)
               [0] {
                  INTEGER 0x01 (1 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x7000025A (1879048794 decimal)
               [0] {
                  INTEGER 0x01 (1 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x30000003 (805306371 decimal)
               [0] {
                  INTEGER 0x0100 (256 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x30000008 (805306376 decimal)
               [0] {
                  INTEGER 0x0080 (128 decimal)
               }
            }
            SEQUENCE {
               INTEGER 0x00900002BC (2415919804 decimal)
               [1] {
                  OCTETSTRING 61
               }
            }
            SEQUENCE {
               INTEGER 0x0090000259 (2415919705 decimal)
               [1] {
                  OCTETSTRING 6D65
               }
            }
            SEQUENCE {
               INTEGER 0x0090001388 (2415924104 decimal)
               [1] {
                  OCTETSTRING 784D473DD1C619981FFFDCF8
               }
            }
         }
      }
   }
```


### Keymaster TA Control Flow

Upon receiving control from an API call (from our client or from the Keymaster HAL), the Keymaster TA has the following flow in `TA_InvokeCommandEntryPoint`:

- Validates the parameter types for the input and output buffers and makes sure that the memory references that are sent from the Normal World belong to the REE.
- Parses the input buffer as an ASN.1 structure `indata` and validates it.
- Calls the appropriate command handler based on `indata->cmd`.
- Fills the output buffer with ASN.1 structure `outdata`.

There are more than 21 command handlers in the Keymaster TA, including:

- [swd_add_rng_entropy](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#383)
- [swd_export_key](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#644)
- [swd_import_key](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#507)
- [swd_get_key_characteristics](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#621)
- [swd_begin](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#1077)
- [swd_update](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#1194)
- [swd_finish](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#1305)
- [swd_abort](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#1318)
- [swd_generate_key](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#472)
- swd_encrypt_key
- [swd_key_attest](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#799)
- swd_configure
- [swd_key_upgrade](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#836)
- swd_generate_sak
- swd_install_gak
- [swd_import_wrapped_key](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#589)
- [swd_compute_shared_hmac](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#330)
- [swd_get_hmac_sharing_parameter](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#234)
- [swd_verify_authorization](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal#363)
- swd_generate_csr
- swd_install_sgak

Some of the entry points are not documented in the [Keymaster API](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal), for instance `swd_encrypt_key`.

### Keymaster TA and HAL in TEEGRIS vs QSEE vs Kinibi

We saw that the Keymaster TA is similar across different models (both Exynos/Snapdragon variants) of S9, S10, S20, and S21. The only difference was in TZOS-specific (Kinibi/TEEGRIS/QSEE) functions that should be logically equivalent (e.g., syscalls and calls to cryptographic engine).

The main functionality is the same, including the vulnerable flows that we describe.
The S9 models have a minor variation that makes it them more vulnerable, as we discuss in the paper.

The following table describes the locations of the Keymaster TA and Keymaster HAL in the different TZOS:

| TZOS      | Keymaster TA                                                      | Keymaster HAL                                 |
|-----------|-------------------------------------------------------------------|-----------------------------------------------|
| TEEGRIS   | `/vendor/tee/00000000-0000-0000-0000-4b45594d5354`                | `/vendor/lib64/libkeymaster_helper_vendor.so` |
| QSEE      | `/vendor/firmware_mnt/image/skeymast`                             | `/vendor/lib64/libkeymaster_helper.so`        |
| Kinibi    | `/vendor/app/mcRegistry/ffffffff00000000000000000000003e.tlbin`   | `/vendor/lib64/libkeymaster_helper_vendor.so` |


### Encryption/Decryption of key blobs

The Keymaster TA encrypts/decrypts key blobs using a function called `tz_wrap`/`tz_unwrap`, which calls a TZOS-specific function to use the cryptographic engine (e.g., in TEEGRIS it calls `TEES_WrappedWithREK`/`TEES_DeriveKeyKDF` from `libteesl.so`).

#### Examples of flows that encrypt/decrypt key blobs

The following figure shows some the flow that call `tz_unwrap`:

![tz_unwrap_graph.png](/images/tz_unwrap_graph.png "tz_unwrap_graph.png")


The following figure shows some the flow that call `tz_wrap`:

![tz_wrap_graph.png](/images/tz_wrap_graph.png "tz_wrap_graph.png")


#### Key parameters of blob-creating commands

Blob-creating commands (such as `swd_generate_key` and `swd_import_key`) accept key parameters that are delivered in the `indata` structure. The parameters control how the key is generated and are also placed inside the blob. They are subsequently used during the cryptographic operations that take the blob as input. Key parameters include:

- Cipher information including:
    - Algorithm (RSA/EC/AES/DES/HMAC)
    - Key size (e.g., 768/1024/2048/3072/4096 for RSA or 128/192/256 for AES)
    - Mode of operation (e.g., ECB/CBC/CTR/GCM)
    - Padding (e.g., none/RSA-OAEP/RSA-PSS)
    - Digest (e.g., none/md5/sha1/sha256)
- The parameters can also include optional access control restrictions on the created blob, including:
    - Purpose (e.g., limit to encryption/signing only, or only encryption and decryption).
    - Maximum number of uses per boot / minimum seconds between operations / expiration date.
    - Require authentication (e.g., by password or biometric prompt) or confirmation by the user.

Key parameters are also known as "tags". We mention the following tags (that are not documented in the official API):

- `KM_TAG_EKEY_BLOB_IV` (value `0x90001388`, type bytes)
- `KM_TAG_HEK_RANDOMNESS` (value `0x90001392`, type bytes)
- `KM_TAG_EKEY_BLOB_ENC_VER` (value `0x30001390`, type integer)
- `KM_TAG_EXPORTABLE` (value `0x7000025a`, type boolean)


#### Hardware protection

To ensure that key blobs are hardware-protected, the device uses the following keys:

- Root Encryption Key (REK): a 256-bit AES key that is available only in secure hardware and is device-unique.
- Hardware Derived Key (HDK): a 256-bit AES key that is derived from the REK per blob encryption using the Key Derivation Function (KDF) which we discussed in the paper.

#### How the Keymaster TA computes the encryption key

The AES encryption key in the Keymaster TA is derived from a "salt" that the function `swd_get_salt` computes - which is the SHA-256 digest of a concatenation of values.
The salt depends on the `enc_ver` ("encryption version") tag in the encrypted key blob, as well as on the application id and application data tags, and is used to derive an encryption key (HDK) from the hardware REK (Root Encryption Key) in a unique way (different keys per application).

We refer to values of `enc_ver` symbolically as either `v15`, `v20_s9` or `v20_s10` based on the constant strings that are used by the KDF and the device model we observed them on (technically `enc_ver` is a byte value).

The following figure illustrates how the salt is computed:
![salt.png](/images/salt.png "salt.png")

On the S8 the `v15` KDF is used. On the S9 by default new blobs are created using `v20-s9`, and on the S10 and later models, by default, the `v20-s10` KDF version is used.

However on the S9, S10, and later models the KDF version can be overridden by the Normal World caller by specifying the tag `KM_TAG_EKEY_BLOB_ENC_VER` when generating a new key: this can be used to force the creation of a `v15` blob. The fact that the latent code to generate and use `v15` blobs exists on newer devices such as S10, S20, and S21 is at the heart of our downgrade attack.

#### Encryption/Decryption fields

At a high level, the AES operation uses the following fields:

- The IV, that is either generated or is located in the parameters that are required for decryption (`KM_TAG_EKEY_BLOB_IV`)
- The AAD that is computed in `swd_get_aad`
- The data to encrypt/decrypt
- The authentication tag for decryption (`KM_TAG_EKEY_BLOB_AUTH_TAG`)
- A salt value that is computed in `swd_get_salt` and is used by KDF to derive the HDK from the REK. 

#### Key blob encryption

The function `swd_encrypt_ekey` is responsible for encrypting key blobs. On Galaxy S9, it does the following:

1. Extracts `enc_ver` from the encrypted key blob: uses `km_get_tag` with `KM_TAG_EKEY_BLOB_ENC_VER`, and if it fails uses `ekey_blob->enc_ver` (the ASN1 integer in the ekey).
2. Computes the salt using `swd_get_salt` (with `enc_ver` and key parameters)
3. `swd_get_iv` **tries to get 12 bytes of IV from the ekey blob** (`KM_TAG_EKEY_BLOB_IV`), otherwise generates a random IV (`RAND_bytes`).
4. Computes the AAD (Additional Authenticated Data) using `swd_get_aad`
5. Calls `tz_wrap` with the plaintext key material (serialized as ASN.1), the computed salt, IV and AAD.

On Galaxy S10, S20, and S21, `swd_encrypt_ekey` does the following:

1. Extracts `enc_ver` from the encrypted key blob: uses `km_get_tag` with `KM_TAG_EKEY_BLOB_ENC_VER`, and if it fails uses `ekey_blob->enc_ver` (the ASN1 integer in the ekey).
2. Generates 16 random bytes for `hek_randomness`
3. Computes the salt using `swd_get_salt` (with `enc_ver` and `hek_randomness`)
4. Computes the AAD (Additional Authenticated Data) using `swd_get_aad`
5. `_swd_get_iv` **tries to get 12 bytes of IV from the ekey blob** (`KM_TAG_EKEY_BLOB_IV`), otherwise generates a random IV (`RAND_bytes`).
6. Calls `tz_wrap` with the plaintext key material (serialized as ASN.1), the computed salt, IV and AAD.

Internally, `tz_wrap` calls TZOS-specific functions (such as`TEES_WrappedWithREK` or `TEES_DeriveKeyKDF` on TEEGRIS) to derive a key from the hardware REK and use it for the AES-GCM operation.

#### Crypto driver in TEEGRIS

The decryption/encryption of ASN.1-serialized key material occurs in the `tz_unwrap`/`tz_wrap` functions (resp.), which call `TEES_WrappedWithREK`/`TEES_DeriveKeyKDF` from `libteesl.so`, which in turn does a ioctl to the crypto driver (`dev://crypto`).

The following figure[^1] illustrates the two flows that use the salt, IV, AAD, and authentication tag to perform the cryptographic wrapping/unwrapping in TEEGRIS:
![teegris_key_wrap.png](/images/teegris_key_wrap.png "teegris_key_wrap.png")

If the length of the ASN.1-serialized key is at most 4096 bytes, the Keymaster TA calls the `TEES_WrappedWithREK` library function to derive the HDK from the salt and then perform AES-GCM in the crypto engine. Conversely, if the length is greater than 4096 bytes, the Keymaster TA uses the `TEES_DeriveKeyKDF` library function to derive the HDK by calling the crypto driver, and then uses a software implementation of AES-GCM-256 (using the SCrypto library that is based on BoringSSL) to perform the encryption.

In order to understand how the key blobs are encrypted, we reversed engineered TEEGRIS, found the `dev://crypto` driver and analysed its ioctl method. We focus on two specific ioctl commands: `CRYPT_FUNC_WRAPPED_WITH_REK` (that encrypts or decrypts key blobs) and `CRYPT_FUNC_KDF` (that derives a HDK from the REK), that are called from `TEES_WrappedWithREK`/`TEES_DeriveKeyKDF` in the Keymaster TA (resp.).

`CRYPT_FUNC_WRAPPED_WITH_REK` checks that the calling task in TEEGRIS is the Keymaster TA by comparing the current UID to the UID of the Keymaster (10 bytes of null, then "KEYMST") and rejects any other task. It then copies the struct that the Keymaster TA sent to DMA memory, edits the salt by appending the Keymaster TA's own UID (16 bytes) and executes an SMC instruction (passing the physical address of the memory where the struct resides as the third argument). If the SMC returns 0, the modified struct is copied back to the Keymaster TA.

`CRYPT_FUNC_KDF` also calls the same SMC function but with a different arguments (0 as the first argument instead of 1). It computes the SHA-256 digest of the KDF key, the task UID and group and the salt, then passes the address of the struct that contains both the hash and the HDK (with its length). The SMC fills the bytes of the HDK.

## Exploiting the Keymaster TA

### IV Reuse

See [IV reuse](/poc/iv_reuse/README.md) for more details and proof-of-concept attacks.

TL;DR: A privileged attacker can specify an IV during key generation/import, and this IV will be used in the AES-GCM encryption of the key material - as mentioned above, `swd_encrypt_ekey` uses the `KM_TAG_EKEY_BLOB_IV` tag (that an attacker fully controls) if it is given (otherwise, a random IV is used).

This means that if an attacker can force the AES encryption key to be the same as the key that encrypted a different blob, they will be able to generate a collision - two ciphertexts that were encrypted using the same key and IV.

**On Galaxy S9, the salt is deterministic so given an application ID and application data the encryption key will be constant, therefore an attacker can set the IV of a new key blob to be equal to a different key blob and generate a collision - thus compromising any key blob.**

Given key blob `blob_A` with unknown key `key_A`, an attacker can import another blob `blob_B` with a known key `key_B` that was encrypted using the same IV and the same salt - which means the same hardware-derived key `HDK` is used in the AES operation - then xor `blob_A` with `blob_B` and `key_B` to fully recover `key_A`, since:

```
blob_A xor blob_B xor key_B = (E(HDK, IV) xor key_A) xor (E(HDK, IV) xor key_B) xor key_B =
(key_B xor key_B) xor key_A = key_A
```

To get the same IV, we pass the same value of `KM_TAG_EKEY_BLOB_IV` from `blob_A` when creating `blob_B`.

`v15` key blobs are immediately vulnerable to the IV reuse attack: since they are only determined by the application ID and application data (and a constant string), an attacker can generate/import a key using the same IV, application ID and application data (given in ekey blob parameters) and create a collision.

`v20-s9` key blobs on Galaxy S9 are also immediately vulnerable - as the key is deterministic (as a function of the application ID and application data and other constant strings), an attacker can force an IV and create a collision. Thus, all key blobs on the S9 are vulnerable.

#### Finding the offset of the encrypted key material

An ASN.1 string includes a type (e.g. integer/octet string), length and value. Possible values for type include:

- `0x2` for `ASN1_INTEGER`
- `0x4` for `ASN1_OCTET_STRING`
- `0x30` for `ASN1_SEQUENCE`
- `0x31` for `ASN1_SET`

`ekey_blob->ekey` is an ASN.1 string that is the AES-256-GCM encryption of an ASN.1 string of a key blob (i.e., `km_key_blob_t`). A key blob includes an `ASN1_INTEGER` for version, `ASN1_OCTET_STRING` for key material and a `SET` of key parameters.

Let `num_bytes` be a function that returns the number of bytes that is required to represent a given integer. Let `ekey_blob` be a blob that represents a key blob for a key whose material is of length `key_len`.

We are interested in the offset of the key material in the encrypted key blob `ekey_blob->ekey`, which contains the following:

- 1 byte of type for the key blob: `0x30`
- `num_bytes(ekey->length)` bytes of length, depending on total string length `ekey->length`
- 1 byte of type for ASN1_INTEGER (`key_blob->ver`): `0x2`
- 1 byte of length for ASN1_INTEGER (`key_blob->ver`): `0x1`
- 1 byte of value for ASN1_INTEGER (`key_blob->ver`): E.g. `0x2` (in current version)
- 1 byte of type for ASN1_OCTET_STRING (`key_blob->key`): `0x4`
- `num_bytes(key_len)` bytes of length, depending on key length (`key_len`)
- `key_len` bytes of value for ASN1_OCTET_STRING (`key_blob->key`)

That is, `6 + num_bytes(ekey->length) + num_bytes(key_len)` bytes until we reach key material.

See [attack.c](/jni/core/attack.c) for the implementation of the IV reuse attack (that finds the offset of encrypted key materials and performs the xor operation).

### Downgrade Attack

See [downgrade attack](/poc/downgrade/README.md) for more details and proof-of-concept attacks.

TL;DR: A privileged attacker in the Normal World can set the `KM_EKEY_BLOB_ENC_VER` tag in the ekey blob that the Keymaster TA checks in order to decide whether to encrypt with `v15` or `v20` encryption version. The latent code for the `v15` encryption version uses a deterministic KDF, therefore an attacker can perform the IV reuse attack on AES-GCM and recover the full key material.

### Persistence of `v15` key blobs

According to the [Keymaster API](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal), key blobs become "old" when the Keymaster device is updated or when the Normal World OS is upgraded to a newer version. When a key becomes "old", the API functions (such as `getCharacteristics`/`begin`)
return a special error code that indicates that the key must be "upgraded".

The Keymaster API exposes the `upgradeKey` method which unwraps (decrypts) the key, examines the OS versions inside the key parameters and compares them to the current OS version. If the current OS version is higher it "upgrades" the key by wrapping (encrypting) it again (and adding the current OS version to the key parameters list).

However, we found that the key parameters that are used in the new blob's wrapping are the same as those in the old key. As any key blob created by our downgrade attack includes the encryption version parameter (`KM_TAG_EKEY_BLOB_ENC_VER`), "upgrading" such a downgraded  `v15` key blob will result in a new but still vulnerable `v15` blob.

According to Samsung, this is the intended behavior, and since the S10 and newer devices have `v20-s10` as the default version, no `v15` key should exist "in the wild". From their response:

> The key blob version is information about what data is bound to the KEK (Key Encryption Key) that encrypts the key blob. And, the upgradeKey API is used when a device is upgraded to an image with more recent Security Patch Level information, and it does not upgrade the key blob version, but updates the SPL (Security Patch Level) value in the key blob to the latest. In other words, it is our intended behavior that the key blob version is not upgraded.

However, this behavior of the `upgradeKey` function allows our downgrade attack (that forces blobs to be created as `v15`) to persist through firmware updates.

---

There are two reasons for the appearance of `KM_TAG_EKEY_BLOB_ENC_VER` inside the key blob:

1. `km_pack_key_data` (responsible for encrypting the key) creates a key blob and sets the blob parameters (`key_blob->par`) to the input parameters (client controlled).
2. When serializing to ASN.1, the function `km_mark_hidden_tags` marks tags that should be removed (e.g. application ID/data, other `KM_EKEY_TAG_*` tags) so that they won't appear in the `getKeyCharacteristics` API and reveal information.

In both cases, the `KM_TAG_EKEY_BLOB_ENC_VER` is not checked and remains in the key blob - this can be observed by calling `getKeyCharacteristics` on a v15 blob.

### Bonus: Export of raw symmetric key material

According to the [Keymaster API](https://android.googlesource.com/platform/hardware/interfaces/+/master/keymaster/4.0/IKeymasterDevice.hal) (or [Keymaster Functions](https://source.android.com/security/keystore/implementer-ref#export_key)), `exportKey` should only export the public key of an asymmetric key pair (RSA/EC) and support only `KeyFormat::X509` for the key format.

However, we discovered that in Samsung devices `swd_export_key` (responsible for the export command of the Keymaster TA) also allows to export raw symmetric key material (AES/DES) if a particular tag `KM_TAG_EXPORTABLE` (value `0x7000025a`, type boolean) exists in the key parameters (that is, `swd_export_key` supports `KeyFormat::RAW`). When we create a symmetric key with this tag and run the export command we get the plaintext key material.

This seems to be a remainder of the [Keymaster2 API](https://android.googlesource.com/platform/hardware/libhardware/+/master/include/hardware/keymaster_defs.h#133), and overall should probably not exist, as an exportable private key can be easily compromised.

According to Samsung, this is not considered as an issue as "the tag (km_tag_exportable) related operation has been removed from the Android P OS and remains only as a legacy code, so it does not operate in the application". Samsung said they will deprecate the `KM_TAG_EXPORTABLE` tag as part of their plan to remove unnecessary code in response to our report.

[^1]: Designed using resources from Flaticon.com
