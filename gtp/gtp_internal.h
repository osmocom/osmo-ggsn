#pragma once

#include <stdint.h>
#include <talloc.h>

uint64_t gtp_imsi_str2gtp(const char *str);

extern TALLOC_CTX *tall_libgtp_ctx;
