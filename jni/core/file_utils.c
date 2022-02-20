#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <skeymaster_log.h>
#include <file_utils.h>


KM_Result read_file(
    const char *directory,
    const char *filename,
    uint8_t **p_data,
    size_t *len)
{
    KM_Result ret = KM_RESULT_INVALID;

    FILE *f = NULL;
    char *full_path = NULL;

    if (NULL == p_data || NULL == len) {
        LOGE("%s", "Invalid arguments");
        goto cleanup;
    }

    size_t full_size = strlen(directory) + strlen(filename) + 1;
    if (full_size < strlen(directory) || full_size < strlen(filename)) {
        LOGE("potential overflow %s", "full_size");
        goto cleanup;
    }

    full_path = malloc(full_size);
    if (NULL == full_path) {
        LOGE("%s failed", "malloc");
        goto cleanup;
    }

    strcpy(full_path, directory);
    strcpy(full_path + strlen(directory), filename);
    full_path[full_size - 1] = '\0';

    f = fopen(full_path, "rb");

    if (NULL == f) {
        LOGE("fopen failed for %s", full_path);
        goto cleanup;
    }

    struct stat finfo;
    if (0 != fstat(fileno(f), &finfo)) {
        LOGE("%s failed", "fstat");
        goto cleanup;
    }

    size_t size = finfo.st_size;
    uint8_t *data = malloc(size * sizeof(*data));
    if (NULL == data) {
        LOGE("%s failed for data", "malloc");
        goto cleanup;
    }

    if (size != fread(data, 1, size, f)) {
        LOGE("%s failed", "fread");
        free(data);
        goto cleanup;
    }

    *p_data = data;
    *len = size;

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != f) {
        fclose(f);
    }

    if (NULL != full_path) {
        free(full_path);
    }

    return ret;
}

KM_Result write_file(
    const char *directory,
    const char *filename,
    const uint8_t *data,
    size_t len)
{
    KM_Result ret = KM_RESULT_SUCCESS;

    FILE *f = NULL;
    char *full_path = NULL;

    size_t full_size = strlen(directory) + strlen(filename) + 1;
    if (full_size < strlen(directory) || full_size < strlen(filename)) {
        LOGE("potential overflow %s", "full_size");
        goto cleanup;
    }

    full_path = malloc(full_size);
    if (NULL == full_path) {
        LOGE("%s failed", "malloc");
        goto cleanup;
    }

    strcpy(full_path, directory);
    strcpy(full_path + strlen(directory), filename);
    full_path[full_size - 1] = '\0';

    f = fopen(full_path, "wb");
    if (NULL == f) {
        LOGE("fopen failed for %s", full_path);
        goto cleanup;
    }

    if (len != fwrite(data, 1, len, f)) {
        LOGE("%s failed", "fwrite");
        goto cleanup;
    }

    LOGI("created %s", full_path);

    ret = 0;

cleanup:
    if (NULL != f) {
        fclose(f);
    }
    if (NULL != full_path) {
        free(full_path);
    }
    return ret;
}

KM_Result save_related_file(
    const char *original_path,
    const char *prefix,
    const char *suffix,
    const uint8_t *data,
    size_t len)
{
    KM_Result ret = KM_RESULT_INVALID;

    char *new_path = NULL;
    size_t full_size = strlen(prefix) + strlen(original_path) + strlen(suffix) + 1;
    if (full_size < strlen(prefix) || full_size < strlen(original_path) || full_size < strlen(suffix)) {
        LOGE("potential overflow %s", "full_size");
        goto cleanup;
    }

    new_path = malloc(full_size);
    sprintf(new_path, "%s%s%s", prefix, original_path, suffix);
    new_path[full_size - 1] = '\0';

    if (KM_RESULT_SUCCESS != WRITE_FILE(new_path, data, len)) {
        goto cleanup;
    }

    ret = KM_RESULT_SUCCESS;

cleanup:
    if (NULL != new_path) {
        free(new_path);
    }
    return ret;
}
