#ifndef _SKEYMASTER_API_H_
#define _SKEYMASTER_API_H_

#include <skeymaster_defs.h>
#include <skeymaster_key_request.h>

/** @brief Initializes required SOs and starts keymaster
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result prepare_keymaster(void);

/** @brief Generate a key
    @param[in]      req             Key request
    @param[in,out]  ekey_path       Output ekey path
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result do_generate(key_request_t *req, const char *ekey_path);

/** @brief Get key characteristics
    @param[in]      req             Key request
    @param[in]      ekey_path       Input ekey path
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result do_get_characteristics(key_request_t *req, const char *ekey_path);

/** @brief Import a key
    @param[in]      req             Key request
    @param[in]      key_path        Input key path
    @param[in,out]  ekey_path       Output ekey path
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result do_import(key_request_t *req, const char *key_path, const char *ekey_path);

/** @brief Export an ekey
    @param[in]      req             Key request
    @param[in]      ekey_path       Input ekey path
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result do_export(key_request_t *req, const char *ekey_path);

/** @brief Upgrade an ekey
    @param[in]      req             Key request
    @param[in]      ekey_path       Input ekey path
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result do_upgrade(key_request_t *req, const char *ekey_path);

/** @brief Begin a cryptographic operation
    @param[in]      req             Key request
    @param[in]      ekey_path       Input ekey path
    @Return         status          KM_RESULT_SUCCESS if successful
  */
KM_Result do_begin(key_request_t *req, const char *ekey_path);

#endif // _SKEYMASTER_API_H_
