#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include <skeymaster_log.h>
#include <file_utils.h>
#include <skeymaster_defs.h>
#include <skeymaster_utils.h>
#include <skeymaster_libs.h>
#include <skeymaster_api.h>
#include <attack.h>

int main(int argc, char * const * argv)
{
    KM_Result ret = KM_RESULT_INVALID;

    key_request_t req;
    memset(&req, 0, sizeof(req));

    if (2 > argc) {
        LOG_USAGE(USAGE_DEFAULT);
        goto cleanup;
    }

    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"cmd", required_argument, 0, 'c'},
        {"application-id", required_argument, 0, 'i'},
        {"application-data", required_argument, 0, 'd'},
        {"ekey-path", required_argument, 0, 'e'},
        {"path", required_argument, 0, 'p'},
        {"second-ekey-path", required_argument, 0, 's'},
        {"output", required_argument, 0, 'o'},
        {"algorithm", required_argument, 0, 0},
        {"purpose", required_argument, 0, 0},
        {"padding", required_argument, 0, 0},
        {"digest", required_argument, 0, 0},
        {"plain", no_argument, 0, 0},
        {"key-size", required_argument, 0, 0},
        {"enc-ver", required_argument, 0, 0},
        {"exportable", no_argument , 0, 0},
        {"request", required_argument, 0, 0},
        {"salt", required_argument, 0, 0},
        {"iv", required_argument, 0, 0},
        {"aad", required_argument, 0, 0},
        {"auth_tag", required_argument, 0, 0},
        {"nonce", required_argument, 0, 0},
        {0}
    };

    const char *cmd = NULL;
    const char *ekey_path = NULL;
    const char *path = NULL;
    const char *second_ekey_path = NULL;
    const char *output = NULL;
    const char *option = NULL;

    // defaults
    req.algorithm = KM_ALGORITHM_AES;
    req.purpose = -1;
    req.padding = -1;
    req.digest = KM_DIGEST_NONE;
    req.enc_ver = -1;
    req.mode = KM_MODE_GCM;
    req.public_exponent = 0x10001;
    req.request = 1;

    // setup libraries
    ret = initialize_libs();
    if (KM_RESULT_SUCCESS != ret) {
        LOGE("failed to initialize required SOs; ret: %d", ret);
        goto cleanup;
    }

    // parse CLI
    int c;
    while (1) {
        int options_index = 0;

        c = getopt_long(argc, argv, "h:c:i:d:e:p:s:o:", long_options, &options_index);
        if (-1 == c) {
            break;
        }

        switch (c) {
        case 0:
            option = long_options[options_index].name;

            if (0 == strcmp(option, "algorithm")) {
                req.algorithm = km_algorithm_to_int(optarg);
                if (-1 == req.algorithm) {
                    LOGE("invalid value for algorithm: %s [supported: rsa/ec/aes/des/hmac]", optarg);
                    goto cleanup;
                }
                LOGD("algorithm %s (0x%x)", km_algorithm_to_string(req.algorithm), req.algorithm);
            }
            else if (0 == strcmp(option, "purpose")) {
                req.purpose = km_purpose_to_int(optarg);
                if (-1 == req.purpose) {
                    LOGE("invalid value for purpose: %s [supported: encrypt/decrypt/sign/verify/wrap_key]", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "padding")) {
                req.padding = km_padding_to_int(optarg);
                if (-1 == req.padding) {
                    LOGE("invalid value for padding: %s [supported: none/oaep/pss/pkcs1.5_encyrpt/pkcs1.5_sign/pkcs7]", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "digest")) {
                req.digest = km_digest_to_int(optarg);
                if (-1 == req.digest) {
                    LOGE("invalid value for digest: %s [supported: none/md5/sha1/sha224/sha256/sha384/sha512]", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "plain")) {
                req.is_plain = 1;
            }
            else if (0 == strcmp(option, "enc-ver")) {
                req.enc_ver = strtol(optarg, NULL, 0);

                if (EINVAL == errno || ERANGE == errno || 0 == req.enc_ver) {
                    LOGE("invalid value for enc-vec: %s", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "key-size")) {
                req.key_size = strtol(optarg, NULL, 0);
                if (EINVAL == errno || ERANGE == errno || 0 == req.key_size) {
                    LOGE("invalid value for key-size: %s", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "exportable")) {
                req.is_exportable = 1;
            }
            else if (0 == strcmp(option, "request")) {
                req.request = strtol(optarg, NULL, 0);
                if (EINVAL == errno || ERANGE == errno || (0 != req.request && 1 != req.request)) {
                    LOGE("invalid value for request: %s", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "salt")) {
                if (KM_RESULT_SUCCESS != READ_FILE(optarg, &req.salt.data, &req.salt.len)) {
                        LOGE("failed to read salt %s", optarg);
                        goto cleanup;
                }
                break;
            }
            else if (0 == strcmp(option, "iv")) {
                if (KM_RESULT_SUCCESS != READ_FILE(optarg, &req.iv.data, &req.iv.len)) {
                    LOGE("failed to get iv (%s)", optarg);
                    goto cleanup;
                }
            }
            else if (0 == strcmp(option, "aad")) {
                if (KM_RESULT_SUCCESS != READ_FILE(optarg, &req.aad.data, &req.aad.len)) {
                        LOGE("failed to read aad %s", optarg);
                        goto cleanup;
                }
                break;
            }
            else if (0 == strcmp(option, "auth_tag")) {
                if (KM_RESULT_SUCCESS != READ_FILE(optarg, &req.auth_tag.data, &req.auth_tag.len)) {
                        LOGE("failed to read auth_tag %s", optarg);
                        goto cleanup;
                }
                break;
            }
            else if (0 == strcmp(option, "nonce")) {
                if (KM_RESULT_SUCCESS != READ_FILE(optarg, &req.nonce.data, &req.nonce.len)) {
                    LOGE("failed to get nonce (%s)", optarg);
                    goto cleanup;
                }
            }
            else {
                LOGE("unknown option %s", option);
                goto cleanup;
            }
            break;

        case 'h':
            LOG_USAGE(USAGE_DEFAULT);
            exit(0);
            break;

        case 'c':
            LOGD("cmd %s", optarg);
            cmd = optarg;
            break;

        case 'i':
            LOGD("id %s", optarg);
            if (0 != strcmp("null", optarg)) {
                copy_vector(&req.application_id, (const uint8_t *)optarg, strlen(optarg));
            }
            break;

        case 'd':
            LOGD("data %s", optarg);
            if (0 != strcmp("null", optarg)) {
                copy_vector(&req.application_data, (const uint8_t *)optarg, strlen(optarg));
            }
            break;

        case 'e':
            LOGD("ekey %s", optarg);
            ekey_path = optarg;
            break;

        case 'p':
            LOGD("path %s", optarg);
            path = optarg;
            break;

        case 's':
            LOGD("second_ekey_path %s", optarg);
            second_ekey_path = optarg;
            break;

        case 'o':
            LOGD("output %s", optarg);
            output = optarg;
            break;

        case '?':
            exit(1);
            break;

        default:
            abort();
        }
    }

    if (NULL == cmd) {
        LOGE("invalid cmd %s (specify -c <cmd>)", cmd);
        LOG_USAGE(USAGE_DEFAULT);
        goto cleanup;
    }

    if (0 == strcmp(cmd, CMD_ATTACK)) {
        ret = iv_collision_attack(path, ekey_path, second_ekey_path, output);
    }
    else if (0 == strcmp(cmd, CMD_GENERATE)) {
        ret = do_generate(&req, ekey_path);
    }
    else if (0 == strcmp(cmd, CMD_GET_CHARS)) {
        ret = do_get_characteristics(&req, ekey_path);
    }
    else if (0 == strcmp(cmd, CMD_IMPORT)) {
        ret = do_import(&req, path, ekey_path);
    }
    else if (0 == strcmp(cmd, CMD_EXPORT)) {
        ret = do_export(&req, ekey_path);
    }
    else if (0 == strcmp(cmd, CMD_UPGRADE)) {
        ret = do_upgrade(&req, ekey_path);
    }
    else if (0 == strcmp(cmd, CMD_BEGIN)) {
        ret = do_begin(&req, ekey_path);
    }
    else if (0 == strcmp(cmd, CMD_PARSE_ASN1)) {
        ret = parse_asn1(ekey_path);
    }
    else {
        LOGE("invalid cmd %s", cmd);
        LOG_USAGE(USAGE_DEFAULT);
        goto cleanup;
    }

    if (0 != ret) {
        LOGE("error: %s", km_result_to_string(ret));
        LOG_USAGE(cmd_to_usage(cmd));
    }
    else {
        LOGD("%s", "done");
    }

cleanup:
    free_key_request(&req);
    destroy_libs();

    return ret;
}
