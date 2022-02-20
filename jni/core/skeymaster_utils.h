#ifndef _SKEYMASTER_UTILS_H_
#define _SKEYMASTER_UTILS_H_

#include <skeymaster_defs.h>
#include <skeymaster_asn1.h>
#include <skeymaster_key_request.h>

#define CMD_ATTACK      ("attack")
#define CMD_GENERATE    ("generate")
#define CMD_GET_CHARS   ("get_chars")
#define CMD_IMPORT      ("import")
#define CMD_EXPORT      ("export")
#define CMD_UPGRADE     ("upgrade")
#define CMD_BEGIN       ("begin")
#define CMD_PARSE_ASN1  ("parse_asn1")

#define USAGE_DEFAULT   ("keybuster -c <attack|generate|get_chars|import|export|upgrade|begin|parse_asn1> -i <app_id> -d <app_data> [-e <ekey_path>] [-p <path>]")
#define USAGE_ATTACK    ("keybuster -c attack -i <app_id> -d <app_data> -p <plain1_path> -e <encrypted1_path> -s <encrypted2_path> -o <output_path>")
#define USAGE_GENERATE  ("keybuster -c generate -i <app_id> -d <app_data> -e <ekey_path> --key-size <size>")
#define USAGE_GET_CHARS ("keybuster -c get_chars -i <app_id> -d <app_data> -e <ekey_path>")
#define USAGE_IMPORT    ("keybuster -c import -i <app_id> -d <app_data> -e <ekey_path> -p <key_path>")
#define USAGE_EXPORT    ("keybuster -c export -i <app_id> -d <app_data> -e <ekey_path>")
#define USAGE_UPGRADE   ("keybuster -c upgrade -i <app_id> -d <app_data> -e <ekey_path>")
#define USAGE_BEGIN     ("keybuster -c begin -i <app_id> -d <app_data> -e <ekey_path> --purpose <encrypt/decrypt/sign/verify> --padding none")

/** @brief Return usage string for the given command
    @param[in]      cmd         Command
    @Return         usage       string
*/
const char *cmd_to_usage(const char *cmd);

/** @brief Log given vector
    @param[in]      name        Prefix
    @param[in]      data        The data to log
    @param[in]      len         The length of the data
*/
void print_vec(const char *name, const uint8_t *data, size_t len);

/** @brief Log given ASN1_STRING
    @param[in]      name        Prefix
    @param[in]      string      The ASN1_STRING to log
*/
void print_asn1_string(const char *name, const ASN1_STRING *string);

/** @brief Log given km_param_t
    @param[in]      name        Prefix
    @param[in]      par         The km_param_t to log
*/
void print_km_param(const char *name, const km_param_t *par);

/** @brief Log given km_indata_t
    @param[in]      in          The km_indata_t to log
*/
void print_km_indata(const km_indata_t *in);

/** @brief Log given km_outdata_t
    @param[in]      out          The km_outdata_t to log
*/
void print_km_outdata(const km_outdata_t *out);

/** @brief Log given km_key_blob_t
    @param[in]      key_blob     The km_key_blob_t to log
*/
void print_km_key_blob(const km_key_blob_t *key_blob);

/** @brief Log given km_ekey_blob_t
    @param[in]      key_blob     The km_ekey_blob_t to log
*/
void print_km_ekey_blob(const km_ekey_blob_t *ekey_blob);

/** @brief Log given parameters
    @param[in]      key_blob     The parameters to log
*/
void print_param_set(const keymaster_key_param_set_t *param_set);

/** @brief Log given characteristics
    @param[in]      key_blob     The characteristics to log
*/
void print_characteristics(const keymaster_key_characteristics_t *characteristics);

/** @brief Create hexstring of given buffer
    @param[in]      data        The data to hexlify
    @param[in]      len         The length of the data
    @Return         hexstring   Allocated hex string
*/
char *hexlify(const uint8_t *data, size_t len);

/** @brief Copy into a new buffer
    @param[out]     new         Output copy (should be freed by caller)
    @param[in]      data        The data to copy
    @param[in]      len         The length of the data
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result copy_vector(vector_t *new, const uint8_t *data, size_t len);

/** @brief Replace a key parameter
    @param[out]     par         Output key parameters
    @param[in]      tag         The tag to replace
    @param[in]      param_tag   The key parameter
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result replace_tag(km_param_t *par, keymaster_tag_t tag, param_tag_t *param_tag);

/** @brief Deserialize the ekey blob
    @param[out]     p_ekey_blob Pointer to the deserialized ekey blob
    @param[in]      ekey        Data of the ekey blob
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result get_ekey_blob(km_ekey_blob_t **p_ekey_blob, vector_t *ekey);

/** @brief Print the ASN.1 deserialization of the ekey blob
    @param[in]      ekey        Data of the ekey blob
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result print_deserialized_ekey_blob(vector_t *ekey);

/** @brief Deserialize the ekey blob and extract a specific key parameter/tag
    @param[in]      ekey        Data of the ekey blob
    @param[in]      tag         The tag to extract
    @param[out]     param_tag   The extracted key parameter
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result get_ekey_blob_tag(vector_t *ekey, keymaster_tag_t tag, param_tag_t *param_tag);

/** @brief Deserialize the ekey blob and extract ekey_blob->ekey
    @param[in]      ekey        Data of the ekey blob
    @param[out]     encrypted   ekey_blob->ekey
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result get_ekey_blob_encrypted(vector_t *ekey, vector_t *encrypted);

/** @brief Extract IV and ekey from ekey blob and save it to a "iv-{ekey_path}" and "encrypted-{ekey_path}"
    @param[in]      ekey_path   Path to ekey blob
    @param[in]      ekey        Data of ekey blob
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result save_iv_and_ekey(const char *ekey_path, vector_t *ekey);

/** @brief Parse ASN1 of ekey blob and save IV and ekey
    @param[in]      ekey_path   Path to ekey blob
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result parse_asn1(const char *ekey_path);

/** @brief Deserialize the ekey blob and add aad to its parameters then serialize to modify the ekey blob
    @param[in]      aad         The AAD
    @param[in,out]  ekey        ekey blob (modified if succesful)
    @Return         status      KM_RESULT_SUCCESS if successful
    @note Only works if keyblob hash is not checked (e.g. modified libkeymaster_helper)
*/
KM_Result add_aad_to_ekey(const vector_t *aad, vector_t *ekey);

/** @brief Add application_id and application_data to key parameters
    @param[in]      application_id
    @param[in]      application_data
    @param[out]     param_set   Output key parameters
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result init_basic_param_set(
    vector_t *application_id,
    vector_t *application_data,
    keymaster_key_param_set_t *param_set);

/** @brief Adds key parameters for AES keys
    @param[in]      req         Key request struct based on input from CLI
    @param[out]     param_set   Output key parameters
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result add_aes_parameters(key_request_t *req, keymaster_key_param_set_t *param_set);

/** @brief Adds key parameters for RSA keys
    @param[in]      req         Key request struct based on input from CLI
    @param[out]     param_set   Output key parameters
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result add_rsa_parameters(key_request_t *req, keymaster_key_param_set_t *param_set);

/** @brief Adds key parameters for EC keys
    @param[in]      req         Key request struct based on input from CLI
    @param[out]     param_set   Output key parameters
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result add_ec_parameters(key_request_t *req, keymaster_key_param_set_t *param_set);

/** @brief Adds key parameters
    @param[in]      req         Key request struct based on input from CLI
    @param[out]     param_set   Output key parameters
    @Return         status      KM_RESULT_SUCCESS if successful
*/
KM_Result init_key_request(
    key_request_t *req,
    keymaster_key_param_set_t *param_set);

#endif // _SKEYMASTER_UTILS_H_
