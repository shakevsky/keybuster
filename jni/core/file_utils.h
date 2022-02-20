#ifndef _FILE_UTILS_H_
#define _FILE_UTILS_H_

#include <stdlib.h>

#include <skeymaster_status.h>

#define WRITEABLE_DIR   ("/data/local/tmp/")

#define READ_FILE(filename, p_data, len)    read_file(WRITEABLE_DIR, filename, p_data, len)
#define WRITE_FILE(filename, data, len)     write_file(WRITEABLE_DIR, filename, data, len)

/** @brief Read a file from the given path
    @param[in]      directory       Directory of the file
    @param[in]      filename        The name of the file
    @param[out]     p_data          Pointer to output buffer
    @param[out]     len             Output len
    @Return         status          KM_RESULT_SUCCESS if successful
    @note Unsafe (ok for research tool), output buffer should be freed by caller
*/
KM_Result read_file(
    const char *directory,
    const char *filename,
    uint8_t **p_data,
    size_t *len);

/** @brief Writes a file in the given path
    @param[in]      directory       Directory of the file
    @param[in]      filename        The name of the file
    @param[in]      data            Output buffer
    @param[in]      len             Output len
    @Return         status          KM_RESULT_SUCCESS if successful
    @note Unsafe (ok for research tool)
*/
KM_Result write_file(
    const char *directory,
    const char *filename,
    const uint8_t *data,
    size_t len);

/** @brief Writes a file in "{prefix}{original_path}{suffix}"
    @param[in]      directory       Directory of the file
    @param[in]      filename        The name of the file
    @param[in]      data            Output buffer
    @param[in]      len             Output len
    @Return         status          KM_RESULT_SUCCESS if successful
    @note Unsafe (ok for research tool)
*/
KM_Result save_related_file(
    const char *original_path,
    const char *prefix,
    const char *suffix,
    const uint8_t *data,
    size_t len);

#endif  // _FILE_UTILS_H_
