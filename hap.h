#ifndef hap_h
#define hap_h

#ifdef __cplusplus
extern "C" {
#endif

/*
 GL_ARB_texture_compression_rgtc
 */

enum HapTextureFormat {
    HapTextureFormat_RGB_DXT1 = 0x83F0,
    HapTextureFormat_RGBA_DXT5 = 0x83F3,
    HapTextureFormat_YCoCg_DXT5 = 0x01,
    HapTextureFormat_A_RGTC1 = 0x8DBB
};

enum HapCompressor {
    HapCompressorNone,
    HapCompressorSnappy
};

enum HapResult {
    HapResult_No_Error = 0,
    HapResult_Bad_Arguments,
    HapResult_Buffer_Too_Small,
    HapResult_Bad_Frame,
    HapResult_Internal_Error
};


typedef void (*HapDecodeWorkFunction)(void *p, unsigned int index);
typedef void (*HapDecodeCallback)(HapDecodeWorkFunction function, void *p, unsigned int count, void *info);

unsigned long HapMaxEncodedLength(unsigned int count,
                                  unsigned long *lengths,
                                  unsigned int *textureFormats,
                                  unsigned int *chunkCounts);


unsigned int HapEncode(unsigned int count,
                       const void **inputBuffers, unsigned long *inputBuffersBytes,
                       unsigned int *textureFormats,
                       unsigned int *compressors,
                       unsigned int *chunkCounts,
                       void *outputBuffer, unsigned long outputBufferBytes,
                       unsigned long *outputBufferBytesUsed);

/* void MyHapDecodeCallback(HapDecodeWorkFunction function, void *p, unsigned int count, void *info)
 {
     int i;
     for (i = 0; i < count; i++) {
 
         function(p, i);
     }
 }
 
 */
unsigned int HapDecode(const void *inputBuffer, unsigned long inputBufferBytes,
                       unsigned int index,
                       HapDecodeCallback callback, void *info,
                       void *outputBuffer, unsigned long outputBufferBytes,
                       unsigned long *outputBufferBytesUsed,
                       unsigned int *outputBufferTextureFormat);

unsigned int HapGetFrameTextureCount(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int *outputTextureCount);


unsigned int HapGetFrameTextureFormat(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int index, unsigned int *outputBufferTextureFormat);


unsigned int HapGetFrameTextureChunkCount(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int index, int *chunk_count);

#ifdef __cplusplus
}
#endif

#endif
