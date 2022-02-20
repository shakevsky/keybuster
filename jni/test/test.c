#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <skeymaster_libs.h>
#include <skeymaster_api.h>
#include <test.h>

typedef int (*testcase_t)(void);

int g_done;
size_t g_current_test;
size_t g_num_passed;
int g_stderr_fd;

#define PATH_LOG "/data/local/tmp/test_stderr"

int main(int argc, char * const * argv)
{
    int ret = TEST_FAILED;

    testcase_t testcases[] = {
        // test_utils
        test_cmd_to_usage,
        test_hexlify,
        test_copy_vector,
        test_get_ekey_blob,
        test_get_ekey_blob_tag,
        test_get_ekey_blob_encrypted,
        test_add_aad_to_ekey,
        test_init_basic_param_set,
        test_add_aes_parameters,
        test_add_rsa_parameters,
        test_add_ec_parameters,
        test_init_key_request,

        // test_commands
        test_generate,
        test_get_key_characteristics,
        test_import,
        test_export,
        test_upgrade,
        test_begin,
    };
    size_t num_testcases = sizeof(testcases) / sizeof(*testcases);

    g_current_test = 0;
    g_num_passed = 0;
    g_done = 0;

    puts("logging stderr to " PATH_LOG);
    g_stderr_fd = open(PATH_LOG, O_CREAT | O_RDWR, 0755);
    CHECK(-1 != g_stderr_fd);
    CHECK(-1 != dup2(g_stderr_fd, STDERR_FILENO));

    CHECK_PASS(initialize_libs());
    CHECK_PASS(prepare_keymaster());

    for (int i = 0; i < num_testcases; ++i) {
        testcases[i]();
    }

cleanup:
    printf("Total tests passed: %lu out of %lu\n", g_num_passed, num_testcases);
    g_done = 1;

    if (g_num_passed == num_testcases) {
        ret = 0;
    }
    else {
        ret = 1;
    }

    destroy_libs();

    if (-1 != g_stderr_fd) {
        close(g_stderr_fd);
    }

    return ret;
}
