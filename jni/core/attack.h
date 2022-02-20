#ifndef _ATTACK_H_
#define _ATTACK_H_

/** @brief Recover plaintext by xoring plain1 with encrypted1 and encrypted 2
    @param[in]      plain1_path     Plaintext for known key blob
    @param[in]      ekey1_path      ekey_blob->ekey of the known key blob corresponding to plain1
    @param[in]      ekey2_path      ekey_blob->ekey of a unknown key blob that we wish to recover
    @param[out]     output          Output path where the recovered plaintext will be written
    @Return         status          0 for success
    @note The length of the known blob must be greater or equal to the length of the unknown blob.
          If the known blob is longer, there will be extra bytes after the recovered key.
          See the comment about why this collision attack on AES-GCM works inside the function.
*/
KM_Result iv_collision_attack(
    const char *plain1_path,
    const char *ekey1_path,
    const char *ekey2_path,
    const char *output);

#endif  // _ATTACK_H_
