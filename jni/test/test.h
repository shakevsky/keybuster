#ifndef _TEST_SKEYMASTER_H_
#define _TEST_SKEYMASTER_H_

#include <stdint.h>
#include <skeymaster_key_request.h>

enum test_result_t {
    TEST_SUCCESS = 0,
    TEST_FAILED
};

#define CHECK(cond) if (!(cond)) { goto cleanup; }
#define CHECK_PASS(cond) CHECK(TEST_SUCCESS == cond)

extern int g_done;
extern size_t g_current_test;
extern size_t g_num_passed;
extern int g_stderr_fd;

#define BEGIN_TEST(name) \
    do { \
        g_current_test++; \
        printf("[ ] Testing %s... ",name); \
    } while (0)

#define END_TEST(ret) \
    do { \
        if (TEST_SUCCESS == ret) { \
            ++g_num_passed; \
        } \
        printf("%s\n", (TEST_SUCCESS == ret) ? "success" : "fail"); \
        return ret; \
    } while(0)

void set_default_key_request(key_request_t *req);

int test_cmd_to_usage(void);
int test_hexlify(void);
int test_copy_vector(void);
int test_get_ekey_blob(void);
int test_get_ekey_blob_tag(void);
int test_get_ekey_blob_encrypted(void);

int test_add_aad_to_ekey(void);
int test_init_basic_param_set(void);
int test_add_aes_parameters(void);
int test_add_rsa_parameters(void);
int test_add_ec_parameters(void);
int test_init_key_request(void);

int test_generate(void);
int test_get_key_characteristics(void);
int test_import(void);
int test_export(void);
int test_upgrade(void);
int test_begin(void);

#endif  // _TEST_SKEYMASTER_H_
