#ifndef _LOG_H_
#define _LOG_H_

#include <stdio.h>
#include <android/log.h>

#define  LOG_TAG    ("keybuster")

#define Dprintf(prefix, fmt, ...) fprintf(stderr, "%s%s(), line %i: " fmt "\n", \
        prefix, __func__, __LINE__, __VA_ARGS__)

#define DEBUG

// #define NOLOG

#ifdef NOLOG
#define  LOGE(fmt, ...)  Dprintf("", fmt, __VA_ARGS__)
#define  LOGW(...)
#define  LOGD(...)
#define  LOGI(...)
#else  // NOLOG

#ifndef DEBUG
#define  LOGE(...)  __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define  LOGW(...)  __android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__)
#define  LOGD(...)  __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define  LOGI(...)  __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#else  // DEBUG
#define  LOGE(fmt, ...)  Dprintf("[ERR] ", fmt, __VA_ARGS__)
#define  LOGW(fmt, ...)  Dprintf("[WRN] ", fmt, __VA_ARGS__)
#define  LOGD(fmt, ...)  Dprintf("[DBG] ", fmt, __VA_ARGS__)
#define  LOGI(fmt, ...)  Dprintf("[INF] ", fmt, __VA_ARGS__)
#endif // !DEBUG

#endif // NOLOG

#define LOG_USAGE(usage) LOGE("usage: %s", usage)

#endif // _LOG_H_
