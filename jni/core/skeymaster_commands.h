#ifndef _SKEYMASTER_COMMANDS_H_
#define _SKEYMASTER_COMMANDS_H_

#include <skeymaster_defs.h>

/** @brief Open connection and run the Configure command
    @Return         status  KM_RESULT_SUCCESS if successful
  */
KM_Result wait_for_keymaster(void);

/** @brief Run the GenerateKey command
    @param[in]      req             Key request
    @param[out]  ekey               Output ekey blob data
    @Return         status          0 if successful
  */
KM_Result generate(key_request_t *req, vector_t *ekey);

/** @brief Run the GetKeyCharacteristics command
    @param[in]      req             Key request
    @param[in]      ekey            Ekey blob data
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result get_key_characteristics(key_request_t *req, vector_t *ekey);

/** @brief Run the importKey command
    @param[in]      req             Key request
    @param[in]      key_path        Input key path
    @param[out]     ekey            Output ekey data
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result import(key_request_t *req, vector_t *key_data, vector_t *ekey);

/** @brief Run the exportKey command
    @param[in]      req             Key request
    @param[in]      ekey            Ekey blob data
    @param[in]      exported        Exported data
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result export(key_request_t *req, vector_t *ekey, vector_t *exported);

/** @brief Run the upgradeKey command
    @param[in]      req             Key request
    @param[in]      ekey            Ekey blob data
    @param[out]     new_ekey        Upgraded ekey blob data
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result upgrade(key_request_t *req, vector_t *ekey, vector_t *new_ekey);

/** @brief Run the begin command
    @param[in]      req                Key request
    @param[in]      ekey               Ekey blob data
    @param[out]     operation_handle   Output operation handle
    @Return         status             KM_RESULT_SUCCESS if successful
  */
KM_Result begin_operation(key_request_t *req, vector_t *ekey, int64_t *operation_handle);

KM_Result finish_operation(
    int64_t *operation_handle,
    keymaster_key_param_set_t *update_params,
    vector_t *data,
    vector_t *signature,
    vector_t *result);

#endif // _SKEYMASTER_COMMANDS_H_
