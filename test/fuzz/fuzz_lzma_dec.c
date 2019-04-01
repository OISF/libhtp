#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "LzmaDec.h"

FILE * outfile = NULL;

void fuzz_openFile(const char * name) {
    if (outfile != NULL) {
        fclose(outfile);
    }
    outfile = fopen(name, "w");
}

static void *SzAlloc(ISzAllocPtr p, size_t size) { return malloc(size); }
static void SzFree(ISzAllocPtr p, void *address) { free(address); }
const ISzAlloc g_Alloc = { SzAlloc, SzFree };

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    size_t srcLen;
    size_t dstLen;
    uint8_t *outBuf;
    int r;
    CLzmaDec state;
    ELzmaStatus status;

    //initialization
    if (outfile == NULL) {
        fuzz_openFile("/dev/null");
    }

    if (Size < LZMA_PROPS_SIZE + 8) {
        return 0;
    }
    srcLen = Size - (LZMA_PROPS_SIZE + 8);
    //Limits expectation up to 16 Mo of uncompressed data
    dstLen = (Data[LZMA_PROPS_SIZE+5] << 16) | (Data[LZMA_PROPS_SIZE+6] << 8) | (Data[LZMA_PROPS_SIZE+7]);
    outBuf = malloc(dstLen);
    if (outBuf == NULL) {
        return 0;
    }

    LzmaDec_Construct(&state);
    r = LzmaDec_Allocate(&state, Data, LZMA_PROPS_SIZE, &g_Alloc);
    if (r != 0) {
        printf("fail\n");
    }
    LzmaDec_Init(&state);
    // r = LzmaUncompress(outBuf, &dstLen, Data + LZMA_PROPS_SIZE + 8, &srcLen, Data, LZMA_PROPS_SIZE);
    r = LzmaDec_DecodeToBuf(&state, outBuf, &dstLen,
                            Data + LZMA_PROPS_SIZE + 8, &srcLen,
                            LZMA_FINISH_ANY, &status);
    fprintf(outfile, "(status: %d %d) decompressed %zu bytes out of %zu bytes\n", r, status, dstLen, srcLen);
    LzmaDec_Free(&state, &g_Alloc);

    free(outBuf);

    return 0;
}
