#include "hap.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "snappy-c.h"

#define kHapUInt24Max 0x00FFFFFF

#define kHapCompressorNone 0xA
#define kHapCompressorSnappy 0xB
#define kHapCompressorComplex 0xC

#define kHapFormatRGBDXT1 0xB
#define kHapFormatRGBADXT5 0xE
#define kHapFormatYCoCgDXT5 0xF
#define kHapFormatARGTC1 0x1

/*

 
 Format         Compressor      Byte Code
 ----------------------------------------
 RGB_DXT1       None            0xAB
 RGB_DXT1       Snappy          0xBB
 RGB_DXT1       Complex         0xCB
 RGBA_DXT5      None            0xAE
 RGBA_DXT5      Snappy          0xBE
 RGBA_DXT5      Complex         0xCE
 YCoCg_DXT5     None            0xAF
 YCoCg_DXT5     Snappy          0xBF
 YCoCg_DXT5     Complex         0xCF
 A_RGTC1        None            0xA1
 A_RGTC1        Snappy          0xB1
 A_RGTC1        Complex         0xC1
 */

/*
Frame Section Types
 */
#define kHapSectionMultipleImages 0x0D
#define kHapSectionDecodeInstructionsContainer 0x01
#define kHapSectionChunkSecondStageCompressorTable 0x02
#define kHapSectionChunkSizeTable 0x03
#define kHapSectionChunkOffsetTable 0x04



typedef struct HapChunkDecodeInfo {
    unsigned int result;
    unsigned int compressor;
    const char *compressed_chunk_data;
    size_t compressed_chunk_size;
    char *uncompressed_chunk_data;
    size_t uncompressed_chunk_size;
} HapChunkDecodeInfo;

static unsigned int hap_read_3_byte_uint(const void *buffer)
{
    return (*(uint8_t *)buffer) + ((*(((uint8_t *)buffer) + 1)) << 8) + ((*(((uint8_t *)buffer) + 2)) << 16);
}

static void hap_write_3_byte_uint(void *buffer, unsigned int value)
{
    *(uint8_t *)buffer = value & 0xFF;
    *(((uint8_t *)buffer) + 1) = (value >> 8) & 0xFF;
    *(((uint8_t *)buffer) + 2) = (value >> 16) & 0xFF;
}

static unsigned int hap_read_4_byte_uint(const void *buffer)
{
    return (*(uint8_t *)buffer) + ((*(((uint8_t *)buffer) + 1)) << 8) + ((*(((uint8_t *)buffer) + 2)) << 16) + ((*(((uint8_t *)buffer) + 3)) << 24);
}

static void hap_write_4_byte_uint(const void *buffer, unsigned int value)
{
    *(uint8_t *)buffer = value & 0xFF;
    *(((uint8_t *)buffer) + 1) = (value >> 8) & 0xFF;
    *(((uint8_t *)buffer) + 2) = (value >> 16) & 0xFF;
    *(((uint8_t *)buffer) + 3) = (value >> 24) & 0xFF;
}

#define hap_top_4_bits(x) (((x) & 0xF0) >> 4)

#define hap_bottom_4_bits(x) ((x) & 0x0F)

#define hap_4_bit_packed_byte(top_bits, bottom_bits) (((top_bits) << 4) | ((bottom_bits) & 0x0F))

static int hap_read_section_header(const void *buffer, uint32_t buffer_length, uint32_t *out_header_length, uint32_t *out_section_length, unsigned int *out_section_type)
{

    if (buffer_length < 4U)
    {
        return HapResult_Bad_Frame;
    }

    *out_section_length = hap_read_3_byte_uint(buffer);

    if (*out_section_length == 0U)
    {
     
        if (buffer_length < 8U)
        {
            return HapResult_Bad_Frame;
        }
        *out_section_length = hap_read_4_byte_uint(((uint8_t *)buffer) + 4U);
        *out_header_length = 8U;
    }
    else
    {
        *out_header_length = 4U;
    }

  
    *out_section_type = *(((uint8_t *)buffer) + 3U);
   
    if (*out_header_length + *out_section_length > buffer_length)
    {
        return HapResult_Bad_Frame;
    }

    return HapResult_No_Error;
}

static void hap_write_section_header(void *buffer, size_t header_length, uint32_t section_length, unsigned int section_type)
{
  

    if (header_length == 4U)
    {
        hap_write_3_byte_uint(buffer, (unsigned int)section_length);
    }
    else
    {
        hap_write_3_byte_uint(buffer, 0U);
        hap_write_4_byte_uint(((uint8_t *)buffer) + 4U, section_length);
    }
    
    *(((uint8_t *)buffer) + 3) = section_type;
}

static unsigned int hap_texture_format_constant_for_format_identifier(unsigned int identifier)
{
    switch (identifier)
    {
        case kHapFormatRGBDXT1:
            return HapTextureFormat_RGB_DXT1;
        case kHapFormatRGBADXT5:
            return HapTextureFormat_RGBA_DXT5;
        case kHapFormatYCoCgDXT5:
            return HapTextureFormat_YCoCg_DXT5;
        case kHapFormatARGTC1:
            return HapTextureFormat_A_RGTC1;
        default:
            return 0;
            
    }
}

static unsigned int hap_texture_format_identifier_for_format_constant(unsigned int constant)
{
    switch (constant)
    {
        case HapTextureFormat_RGB_DXT1:
            return kHapFormatRGBDXT1;
        case HapTextureFormat_RGBA_DXT5:
            return kHapFormatRGBADXT5;
        case HapTextureFormat_YCoCg_DXT5:
            return kHapFormatYCoCgDXT5;
        case HapTextureFormat_A_RGTC1:
            return kHapFormatARGTC1;
        default:
            return 0;
    }
}


static size_t hap_decode_instructions_length(unsigned int chunk_count)
{
    /*
     = chunk_count + (4 * chunk_count) + 4 + 4
     */
    size_t length = (5 * chunk_count) + 8;

    return length;
}

static unsigned int hap_limited_chunk_count_for_frame(size_t input_bytes, unsigned int texture_format, unsigned int chunk_count)
{
    // (0xFFFFFF == count + (4 x count) + 20)
    if (chunk_count > 3355431)
    {
        chunk_count = 3355431;
    }
    // Divide frame equally on DXT block boundries (8 or 16 bytes)
    unsigned long dxt_block_count;
    switch (texture_format) {
        case HapTextureFormat_RGB_DXT1:
        case HapTextureFormat_A_RGTC1:
            dxt_block_count = input_bytes / 8;
            break;
        default:
            dxt_block_count = input_bytes / 16;
    }
    while (dxt_block_count % chunk_count != 0) {
        chunk_count--;
    }

    return chunk_count;
}

static size_t hap_max_encoded_length(size_t input_bytes, unsigned int texture_format, unsigned int compressor, unsigned int chunk_count)
{
    size_t decode_instructions_length, max_compressed_length;

    chunk_count = hap_limited_chunk_count_for_frame(input_bytes, texture_format, chunk_count);

    decode_instructions_length = hap_decode_instructions_length(chunk_count);

    if (compressor == HapCompressorSnappy)
    {
        size_t chunk_size = input_bytes / chunk_count;
        max_compressed_length = snappy_max_compressed_length(chunk_size) * chunk_count;
    }
    else
    {
        max_compressed_length = input_bytes;
    }

    return max_compressed_length + 8U + decode_instructions_length + 4U;
}

unsigned long HapMaxEncodedLength(unsigned int count,
                                  unsigned long *inputBytes,
                                  unsigned int *textureFormats,
                                  unsigned int *chunkCounts)
{
    unsigned long total_length = 8;

    // Return 0 for bad arguments
    if (count == 0 || count > 2
        || inputBytes == NULL
        || textureFormats == NULL
        || chunkCounts == NULL)
    {
        return 0;
    }

    for (int i = 0; i < count; i++)
    {
        if (chunkCounts[i] == 0)
        {
            return 0;
        }

        total_length += hap_max_encoded_length(inputBytes[i], textureFormats[i], HapCompressorSnappy, chunkCounts[i]);
    }

    return total_length;
}

static unsigned int hap_encode_texture(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int textureFormat,
                                       unsigned int compressor, unsigned int chunkCount, void *outputBuffer,
                                       unsigned long outputBufferBytes, unsigned long *outputBufferBytesUsed)
{
    size_t top_section_header_length;
    size_t top_section_length;
    unsigned int storedCompressor;
    unsigned int storedFormat;

    if (inputBuffer == NULL
        || inputBufferBytes == 0
        || (textureFormat != HapTextureFormat_RGB_DXT1
            && textureFormat != HapTextureFormat_RGBA_DXT5
            && textureFormat != HapTextureFormat_YCoCg_DXT5
            && textureFormat != HapTextureFormat_A_RGTC1
            )
        || (compressor != HapCompressorNone
            && compressor != HapCompressorSnappy
            )
        || outputBuffer == NULL
        || outputBufferBytesUsed == NULL
        )
    {
        return HapResult_Bad_Arguments;
    }
    else if (outputBufferBytes < hap_max_encoded_length(inputBufferBytes, textureFormat, compressor, chunkCount))
    {
        return HapResult_Buffer_Too_Small;
    }
    
    if (inputBufferBytes > kHapUInt24Max)
    {
        top_section_header_length = 8U;
    }
    else
    {
        top_section_header_length = 4U;
    }

    if (compressor == HapCompressorSnappy)
    {

        size_t decode_instructions_length;
        size_t chunk_size, compress_buffer_remaining;
        uint8_t *second_stage_compressor_table;
        void *chunk_size_table;
        char *compressed_data;
        unsigned int i;

        chunkCount = hap_limited_chunk_count_for_frame(inputBufferBytes, textureFormat, chunkCount);
        decode_instructions_length = hap_decode_instructions_length(chunkCount);

        if ((inputBufferBytes + decode_instructions_length + 4) > kHapUInt24Max)
        {
            top_section_header_length = 8U;
        }

        second_stage_compressor_table = ((uint8_t *)outputBuffer) + top_section_header_length + 4 + 4;
        chunk_size_table = ((uint8_t *)outputBuffer) + top_section_header_length + 4 + 4 + chunkCount + 4;

        chunk_size = inputBufferBytes / chunkCount;

        hap_write_section_header(((uint8_t *)outputBuffer) + top_section_header_length, 4U, decode_instructions_length, kHapSectionDecodeInstructionsContainer);

        hap_write_section_header(((uint8_t *)outputBuffer) + top_section_header_length + 4U, 4U, chunkCount, kHapSectionChunkSecondStageCompressorTable);

        hap_write_section_header(((uint8_t *)outputBuffer) + top_section_header_length + 4U + 4U + chunkCount, 4U, chunkCount * 4U, kHapSectionChunkSizeTable);

        compressed_data = (char *)(((uint8_t *)outputBuffer) + top_section_header_length + 4 + decode_instructions_length);

        compress_buffer_remaining = outputBufferBytes - top_section_header_length - 4 - decode_instructions_length;

        top_section_length = 4 + decode_instructions_length;

        for (i = 0; i < chunkCount; i++) {
            size_t chunk_packed_length = compress_buffer_remaining;
            const char *chunk_input_start = (const char *)(((uint8_t *)inputBuffer) + (chunk_size * i));
            if (compressor == HapCompressorSnappy)
            {
                snappy_status result = snappy_compress(chunk_input_start, chunk_size, (char *)compressed_data, &chunk_packed_length);
                if (result != SNAPPY_OK)
                {
                    return HapResult_Internal_Error;
                }
            }

            if (compressor == HapCompressorNone || chunk_packed_length >= chunk_size)
            {
                memcpy(compressed_data, chunk_input_start, chunk_size);
                chunk_packed_length = chunk_size;
                second_stage_compressor_table[i] = kHapCompressorNone;
            }
            else
            {
                second_stage_compressor_table[i] = kHapCompressorSnappy;
            }
            hap_write_4_byte_uint(((uint8_t *)chunk_size_table) + (i * 4), chunk_packed_length);
            compressed_data += chunk_packed_length;
            top_section_length += chunk_packed_length;
            compress_buffer_remaining -= chunk_packed_length;
        }

        if (top_section_length < inputBufferBytes + top_section_header_length)
        {
            storedCompressor = kHapCompressorComplex;
        }
        else
        {
            compressor = HapCompressorNone;
        }
    }

    if (compressor == HapCompressorNone)
    {
        memcpy(((uint8_t *)outputBuffer) + top_section_header_length, inputBuffer, inputBufferBytes);
        top_section_length = inputBufferBytes;
        storedCompressor = kHapCompressorNone;
    }
    
    storedFormat = hap_texture_format_identifier_for_format_constant(textureFormat);
    
    hap_write_section_header(outputBuffer, top_section_header_length, top_section_length, hap_4_bit_packed_byte(storedCompressor, storedFormat));

    *outputBufferBytesUsed = top_section_length + top_section_header_length;

    return HapResult_No_Error;
}

unsigned int HapEncode(unsigned int count,
                       const void **inputBuffers, unsigned long *inputBuffersBytes,
                       unsigned int *textureFormats,
                       unsigned int *compressors,
                       unsigned int *chunkCounts,
                       void *outputBuffer, unsigned long outputBufferBytes,
                       unsigned long *outputBufferBytesUsed)
{
    size_t top_section_header_length;
    size_t top_section_length;
    unsigned long section_length;

    if (count == 0 || count > 2 
        || inputBuffers == NULL
        || inputBuffersBytes == NULL
        || textureFormats == NULL
        || compressors == NULL
        || chunkCounts == NULL
        || outputBuffer == NULL
        || outputBufferBytes == 0
        || outputBufferBytesUsed == NULL)
    {
        return HapResult_Bad_Arguments;
    }

    for (int i = 0; i < count; i++)
    {
        if (chunkCounts[i] == 0)
        {
            return HapResult_Bad_Arguments;
        }
    }

    if (count == 1)
    {
        return hap_encode_texture(inputBuffers[0],
                                  inputBuffersBytes[0],
                                  textureFormats[0],
                                  compressors[0],
                                  chunkCounts[0],
                                  outputBuffer,
                                  outputBufferBytes,
                                  outputBufferBytesUsed);
    }
    else if ((textureFormats[0] != HapTextureFormat_YCoCg_DXT5 && textureFormats[1] != HapTextureFormat_YCoCg_DXT5)
             && (textureFormats[0] != HapTextureFormat_A_RGTC1 && textureFormats[1] != HapTextureFormat_A_RGTC1))
    {
        return HapResult_Bad_Arguments;
    }
    else
    {
        top_section_length = 0;
        for (int i = 0; i < count; i++)
        {
            top_section_length += inputBuffersBytes[i] + hap_decode_instructions_length(chunkCounts[i]) + 4;
        }

        if (top_section_length > kHapUInt24Max)
        {
            top_section_header_length = 8U;
        }
        else
        {
            top_section_header_length = 4U;
        }

        top_section_length = 0;
        for (int i = 0; i < count; i++)
        {
            void *section = ((uint8_t *)outputBuffer) + top_section_header_length + top_section_length;
            unsigned int result = hap_encode_texture(inputBuffers[i],
                                                     inputBuffersBytes[i],
                                                     textureFormats[i],
                                                     compressors[i],
                                                     chunkCounts[i],
                                                     section,
                                                     outputBufferBytes - (top_section_header_length + top_section_length),
                                                     &section_length);
            if (result != HapResult_No_Error)
            {
                return result;
            }
            top_section_length += section_length;
        }

        hap_write_section_header(outputBuffer, top_section_header_length, top_section_length, kHapSectionMultipleImages);

        *outputBufferBytesUsed = top_section_length + top_section_header_length;

        return HapResult_No_Error;
    }
}

static void hap_decode_chunk(HapChunkDecodeInfo chunks[], unsigned int index)
{
    if (chunks)
    {
        if (chunks[index].compressor == kHapCompressorSnappy)
        {
            snappy_status snappy_result = snappy_uncompress(chunks[index].compressed_chunk_data,
                                                            chunks[index].compressed_chunk_size,
                                                            chunks[index].uncompressed_chunk_data,
                                                            &chunks[index].uncompressed_chunk_size);

            switch (snappy_result)
            {
                case SNAPPY_INVALID_INPUT:
                    chunks[index].result = HapResult_Bad_Frame;
                    break;
                case SNAPPY_OK:
                    chunks[index].result = HapResult_No_Error;
                    break;
                default:
                    chunks[index].result = HapResult_Internal_Error;
                    break;
            }
        }
        else if (chunks[index].compressor == kHapCompressorNone)
        {
            memcpy(chunks[index].uncompressed_chunk_data,
                   chunks[index].compressed_chunk_data,
                   chunks[index].compressed_chunk_size);
            chunks[index].result = HapResult_No_Error;
        }
        else
        {
            chunks[index].result = HapResult_Bad_Frame;
        }
    }
}

static unsigned int hap_decode_header_complex_instructions(const void *texture_section, uint32_t texture_section_length, int * chunk_count,
                                                   const void **compressors, const void **chunk_sizes, const void **chunk_offsets, const char **frame_data){
    int result = HapResult_No_Error;
    const void *section_start;
    uint32_t section_header_length;
    uint32_t section_length;
    unsigned int section_type;
    size_t bytes_remaining = 0;

    *compressors = NULL;
    *chunk_sizes = NULL;
    *chunk_offsets = NULL;

    result = hap_read_section_header(texture_section, texture_section_length, &section_header_length, &section_length, &section_type);

    if (result == HapResult_No_Error && section_type != kHapSectionDecodeInstructionsContainer)
    {
        result = HapResult_Bad_Frame;
    }

    if (result != HapResult_No_Error)
    {
        return result;
    }

    *frame_data = ((const char *)texture_section) + section_header_length + section_length;

    section_start = ((uint8_t *)texture_section) + section_header_length;
    bytes_remaining = section_length;

    while (bytes_remaining > 0) {
        unsigned int section_chunk_count = 0;
        result = hap_read_section_header(section_start, bytes_remaining, &section_header_length, &section_length, &section_type);
        if (result != HapResult_No_Error)
        {
            return result;
        }
        section_start = ((uint8_t *)section_start) + section_header_length;
        switch (section_type) {
            case kHapSectionChunkSecondStageCompressorTable:
                *compressors = section_start;
                section_chunk_count = section_length;
                break;
            case kHapSectionChunkSizeTable:
                *chunk_sizes = section_start;
                section_chunk_count = section_length / 4;
                break;
            case kHapSectionChunkOffsetTable:
                *chunk_offsets = section_start;
                section_chunk_count = section_length / 4;
                break;
            default:
                break;
        }

        if (section_chunk_count != 0)
        {
            if ((*chunk_count) != 0 && section_chunk_count != (*chunk_count))
            {
                return HapResult_Bad_Frame;
            }
            *chunk_count = section_chunk_count;
        }

        section_start = ((uint8_t *)section_start) + section_length;
        bytes_remaining -= section_header_length + section_length;
    }

    
    if (*compressors == NULL || *chunk_sizes == NULL)
    {
        return HapResult_Bad_Frame;
    }
    return result;
}

unsigned int hap_decode_single_texture(const void *texture_section, uint32_t texture_section_length,
                                       unsigned int texture_section_type,
                                       HapDecodeCallback callback, void *info,
                                       void *outputBuffer, unsigned long outputBufferBytes,
                                       unsigned long *outputBufferBytesUsed,
                                       unsigned int *outputBufferTextureFormat)
{
    int result = HapResult_No_Error;
    unsigned int textureFormat;
    unsigned int compressor;
    size_t bytesUsed = 0;

    compressor = hap_top_4_bits(texture_section_type);
    textureFormat = hap_bottom_4_bits(texture_section_type);

    *outputBufferTextureFormat = hap_texture_format_constant_for_format_identifier(textureFormat);
    if (*outputBufferTextureFormat == 0)
    {
        return HapResult_Bad_Frame;
    }

    if (compressor == kHapCompressorComplex)
    {
        int chunk_count = 0;
        const void *compressors = NULL;
        const void *chunk_sizes = NULL;
        const void *chunk_offsets = NULL;
        const char *frame_data = NULL;

        result = hap_decode_header_complex_instructions(texture_section, texture_section_length, &chunk_count, &compressors, &chunk_sizes, &chunk_offsets, &frame_data);

        if (result != HapResult_No_Error)
        {
            return result;
        }

        if (chunk_count > 0)
        {
            HapChunkDecodeInfo *chunk_info = (HapChunkDecodeInfo *)malloc(sizeof(HapChunkDecodeInfo) * chunk_count);

            size_t running_compressed_chunk_size = 0;
            size_t running_uncompressed_chunk_size = 0;
            int i;

            if (chunk_info == NULL)
            {
                return HapResult_Internal_Error;
            }

            for (i = 0; i < chunk_count; i++) {

                chunk_info[i].compressor = *(((uint8_t *)compressors) + i);

                chunk_info[i].compressed_chunk_size = hap_read_4_byte_uint(((uint8_t *)chunk_sizes) + (i * 4));

                if (chunk_offsets)
                {
                    chunk_info[i].compressed_chunk_data = frame_data + hap_read_4_byte_uint(((uint8_t *)chunk_offsets) + (i * 4));
                }
                else
                {
                    chunk_info[i].compressed_chunk_data = frame_data + running_compressed_chunk_size;
                }

                running_compressed_chunk_size += chunk_info[i].compressed_chunk_size;

                if (chunk_info[i].compressor == kHapCompressorSnappy)
                {
                    snappy_status snappy_result = snappy_uncompressed_length(chunk_info[i].compressed_chunk_data,
                        chunk_info[i].compressed_chunk_size,
                        &(chunk_info[i].uncompressed_chunk_size));

                    if (snappy_result != SNAPPY_OK)
                    {
                        switch (snappy_result)
                        {
                        case SNAPPY_INVALID_INPUT:
                            result = HapResult_Bad_Frame;
                            break;
                        default:
                            result = HapResult_Internal_Error;
                            break;
                        }
                        break;
                    }
                }
                else
                {
                    chunk_info[i].uncompressed_chunk_size = chunk_info[i].compressed_chunk_size;
                }

                chunk_info[i].uncompressed_chunk_data = (char *)(((uint8_t *)outputBuffer) + running_uncompressed_chunk_size);
                running_uncompressed_chunk_size += chunk_info[i].uncompressed_chunk_size;
            }

            if (result == HapResult_No_Error && running_uncompressed_chunk_size > outputBufferBytes)
            {
                result = HapResult_Buffer_Too_Small;
            }

            if (result == HapResult_No_Error)
            {
                bytesUsed = running_uncompressed_chunk_size;

                if (chunk_count == 1)
                {
                    hap_decode_chunk(chunk_info, 0);
                }
                else
                {
                    callback((HapDecodeWorkFunction)hap_decode_chunk, chunk_info, chunk_count, info);
                }

                for (i = 0; i < chunk_count; i++)
                {
                    if (chunk_info[i].result != HapResult_No_Error)
                    {
                        result = chunk_info[i].result;
                        break;
                    }
                }
            }

            free(chunk_info);

            if (result != HapResult_No_Error)
            {
                return result;
            }
        }
    }
    else if (compressor == kHapCompressorSnappy)
    {
        snappy_status snappy_result = snappy_uncompressed_length((const char *)texture_section, texture_section_length, &bytesUsed);
        if (snappy_result != SNAPPY_OK)
        {
            return HapResult_Internal_Error;
        }
        if (bytesUsed > outputBufferBytes)
        {
            return HapResult_Buffer_Too_Small;
        }
        snappy_result = snappy_uncompress((const char *)texture_section, texture_section_length, (char *)outputBuffer, &bytesUsed);
        if (snappy_result != SNAPPY_OK)
        {
            return HapResult_Internal_Error;
        }
    }
    else if (compressor == kHapCompressorNone)
    {
        bytesUsed = texture_section_length;
        if (texture_section_length > outputBufferBytes)
        {
            return HapResult_Buffer_Too_Small;
        }
        memcpy(outputBuffer, texture_section, texture_section_length);
    }
    else
    {
        return HapResult_Bad_Frame;
    }
    if (outputBufferBytesUsed != NULL)
    {
        *outputBufferBytesUsed = bytesUsed;
    }
    
    return HapResult_No_Error;
}

int hap_get_section_at_index(const void *input_buffer, uint32_t input_buffer_bytes,
                             unsigned int index,
                             const void **section, uint32_t *section_length, unsigned int *section_type)
{
    int result;
    uint32_t section_header_length;

    result = hap_read_section_header(input_buffer, input_buffer_bytes, &section_header_length, section_length, section_type);

    if (result != HapResult_No_Error)
    {
        return result;
    }

    if (*section_type == kHapSectionMultipleImages)
    {
        size_t offset = 0;
        size_t top_section_length = *section_length;
        input_buffer = ((uint8_t *)input_buffer) + section_header_length;
        section_header_length = 0;
        *section_length = 0;
        for (int i = 0; i <= index; i++) {
            offset += section_header_length + *section_length;
            if (offset >= top_section_length)
            {
                return HapResult_Bad_Arguments;
            }
            result = hap_read_section_header(((uint8_t *)input_buffer) + offset,
                                             top_section_length - offset,
                                             &section_header_length,
                                             section_length,
                                             section_type);
            if (result != HapResult_No_Error)
            {
                return result;
            }
        }
        offset += section_header_length;
        *section = ((uint8_t *)input_buffer) + offset;
        return HapResult_No_Error;
    }
    else if (index == 0)
    {
        *section = ((uint8_t *)input_buffer) + section_header_length;
        return HapResult_No_Error;
    }
    else
    {
        *section = NULL;
        *section_length = 0;
        *section_type = 0;
        return HapResult_Bad_Arguments;
    }
}

unsigned int HapDecode(const void *inputBuffer, unsigned long inputBufferBytes,
                       unsigned int index,
                       HapDecodeCallback callback, void *info,
                       void *outputBuffer, unsigned long outputBufferBytes,
                       unsigned long *outputBufferBytesUsed,
                       unsigned int *outputBufferTextureFormat)
{
    int result = HapResult_No_Error;
    const void *section;
    uint32_t section_length;
    unsigned int section_type;

    if (inputBuffer == NULL
        || index > 1
        || callback == NULL
        || outputBuffer == NULL
        || outputBufferTextureFormat == NULL
        )
    {
        return HapResult_Bad_Arguments;
    }

    result = hap_get_section_at_index(inputBuffer, inputBufferBytes, index, &section, &section_length, &section_type);

    if (result == HapResult_No_Error)
    {
        result = hap_decode_single_texture(section,
                                           section_length,
                                           section_type,
                                           callback, info,
                                           outputBuffer,
                                           outputBufferBytes,
                                           outputBufferBytesUsed,
                                           outputBufferTextureFormat);
    }

    return result;
}

unsigned int HapGetFrameTextureCount(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int *outputTextureCount)
{
    int result;
    uint32_t section_header_length;
    uint32_t section_length;
    unsigned int section_type;

    result = hap_read_section_header(inputBuffer, inputBufferBytes, &section_header_length, &section_length, &section_type);

    if (result != HapResult_No_Error)
    {
        return result;
    }

    if (section_type == kHapSectionMultipleImages)
    {
        uint32_t offset = section_header_length;
        uint32_t top_section_length = section_length;
        *outputTextureCount = 0;
        while (offset < top_section_length) {
            result = hap_read_section_header(((uint8_t *)inputBuffer) + offset,
                                             inputBufferBytes - offset,
                                             &section_header_length,
                                             &section_length,
                                             &section_type);
            if (result != HapResult_No_Error)
            {
                return result;
            }
            offset += section_header_length + section_length;
            *outputTextureCount += 1;
        }
        return HapResult_No_Error;
    }
    else
    {
        *outputTextureCount = 1;
        return HapResult_No_Error;
    }
}

unsigned int HapGetFrameTextureFormat(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int index, unsigned int *outputBufferTextureFormat)
{
    unsigned int result = HapResult_No_Error;
    const void *section;
    uint32_t section_length;
    unsigned int section_type;

    if (inputBuffer == NULL
        || index > 1
        || outputBufferTextureFormat == NULL
        )
    {
        return HapResult_Bad_Arguments;
    }

    result = hap_get_section_at_index(inputBuffer, inputBufferBytes, index, &section, &section_length, &section_type);

    if (result == HapResult_No_Error)
    {

        *outputBufferTextureFormat = hap_texture_format_constant_for_format_identifier(hap_bottom_4_bits(section_type));

        if (*outputBufferTextureFormat == 0)
        {
            result = HapResult_Bad_Frame;
        }
    }
    return result;
}

unsigned int HapGetFrameTextureChunkCount(const void *inputBuffer, unsigned long inputBufferBytes, unsigned int index, int *chunk_count)
{
    unsigned int result = HapResult_No_Error;
    const void *section;
    uint32_t section_length;
    unsigned int section_type;
    *chunk_count = 0;


    if (inputBuffer == NULL
        || index > 1
        )
    {
        return HapResult_Bad_Arguments;
    }

    result = hap_get_section_at_index(inputBuffer, inputBufferBytes, index, &section, &section_length, &section_type);

    if (result == HapResult_No_Error)
    {
        unsigned int compressor;

        compressor = hap_top_4_bits(section_type);

        if (compressor == kHapCompressorComplex)
        {

            const void *compressors = NULL;
            const void *chunk_sizes = NULL;
            const void *chunk_offsets = NULL;
            const char *frame_data = NULL;

            result = hap_decode_header_complex_instructions(section, section_length, chunk_count, &compressors, &chunk_sizes, &chunk_offsets, &frame_data);

            if (result != HapResult_No_Error)
            {
                return result;
            }
        }
        else if ((compressor == kHapCompressorSnappy)||(compressor == kHapCompressorNone))
        {
            *chunk_count = 1;
        }
        else
        {
            return HapResult_Bad_Frame;
        }
    }
    return result;
}
