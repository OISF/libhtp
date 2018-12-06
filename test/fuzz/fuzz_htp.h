/**
 * @file
 * @author Philippe Antoine <contact@catenacyber.fr>
 * fuzz harness for libhtp
 */

#ifndef __FUZZ_HTP_H__
#define __FUZZ_HTP_H__

#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <stdio.h>

#include <sys/stat.h>
#include <fcntl.h>

#include "htp/htp.h"
#include "test/test.h"

void fuzz_openFile(const char * name);
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size);

#endif /* __FUZZ_HTP_H__ */

