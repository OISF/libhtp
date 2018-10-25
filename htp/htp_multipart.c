/***************************************************************************
 * Copyright (c) 2009-2010 Open Information Security Foundation
 * Copyright (c) 2010-2013 Qualys, Inc.
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * - Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.

 * - Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.

 * - Neither the name of the Qualys, Inc. nor the names of its
 *   contributors may be used to endorse or promote products derived from
 *   this software without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 ***************************************************************************/

/**
 * @file
 * @author Ivan Ristic <ivanr@webkreator.com>
 */

#include "htp_config_auto.h"

#include "htp_private.h"

/**
 * Determines the type of a Content-Disposition parameter.
 *
 * @param[in] data
 * @param[in] startpos
 * @param[in] pos
 * @return CD_PARAM_OTHER, CD_PARAM_NAME or CD_PARAM_FILENAME.
 */
static int htp_mpartp_cd_param_type(unsigned char *data, size_t startpos, size_t endpos) {
    if ((endpos - startpos) == 4) {
        if (memcmp(data + startpos, "name", 4) == 0) return CD_PARAM_NAME;
    } else if ((endpos - startpos) == 8) {
        if (memcmp(data + startpos, "filename", 8) == 0) return CD_PARAM_FILENAME;
    }

    return CD_PARAM_OTHER;
}

htp_multipart_t *htp_mpartp_get_multipart(htp_mpartp_t *parser) {
    return &(parser->multipart);
}

/**
 * Decodes a C-D header value. This is impossible to do correctly without a
 * parsing personality because most browsers are broken:
 *  - Firefox encodes " as \", and \ is not encoded.
 *  - Chrome encodes " as %22.
 *  - IE encodes " as \", and \ is not encoded.
 *  - Opera encodes " as \" and \ as \\.
 * @param[in] b
 */
static void htp_mpart_decode_quoted_cd_value_inplace(bstr *b) {
    unsigned char *s = bstr_ptr(b);
    unsigned char *d = bstr_ptr(b);
    size_t len = bstr_len(b);
    size_t pos = 0;

    while (pos < len) {
        // Ignore \ when before \ or ".
        if ((*s == '\\')&&(pos + 1 < len)&&((*(s + 1) == '"')||(*(s + 1) == '\\'))) {
            s++;
            pos++;
        }

        *d++ = *s++;
        pos++;
    }

    bstr_adjust_len(b, len - (s - d));
}

/**
 * Parses the Content-Disposition part header.
 *
 * @param[in] part
 * @return HTP_OK on success (header found and parsed), HTP_DECLINED if there is no C-D header or if
 *         it could not be processed, and HTP_ERROR on fatal error.
 */
htp_status_t htp_mpart_part_parse_c_d(htp_multipart_part_t *part) {
    // Find the C-D header.
    htp_header_t *h = htp_table_get_c(part->headers, "content-disposition");
    if (h == NULL) {        
        part->parser->multipart.flags |= HTP_MULTIPART_PART_UNKNOWN;
        return HTP_DECLINED;
    }

    // Require "form-data" at the beginning of the header.
    if (bstr_index_of_c(h->value, "form-data") != 0) {        
        part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
        return HTP_DECLINED;
    }

    // The parsing starts here.
    unsigned char *data = bstr_ptr(h->value);
    size_t len = bstr_len(h->value);
    size_t pos = 9; // Start after "form-data"

    // Main parameter parsing loop (once per parameter).
    while (pos < len) {              
        // Ignore whitespace.
        while ((pos < len) && isspace(data[pos])) pos++;
        if (pos == len) {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }

        // Expecting a semicolon.
        if (data[pos] != ';') {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }
        pos++;

        // Go over the whitespace before parameter name.
        while ((pos < len) && isspace(data[pos])) pos++;
        if (pos == len) {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }

        // Found the starting position of the parameter name.
        size_t start = pos;

        // Look for the ending position.
        while ((pos < len) && (!isspace(data[pos]) && (data[pos] != '='))) pos++;
        if (pos == len) {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }

        // Ending position is in "pos" now.

        // Determine parameter type ("name", "filename", or other).
        int param_type = htp_mpartp_cd_param_type(data, start, pos);        

        // Ignore whitespace after parameter name, if any.
        while ((pos < len) && isspace(data[pos])) pos++;
        if (pos == len) {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }

        // Equals.
        if (data[pos] != '=') {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }
        pos++;

        // Go over the whitespace before the parameter value.
        while ((pos < len) && isspace(data[pos])) pos++;
        if (pos == len) {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }
        
        // Expecting a double quote.
        if (data[pos] != '"') {            
            // Bare string or non-standard quoting, which we don't like.
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }        

        pos++; // Over the double quote.

        // We have the starting position of the value.
        start = pos;

        // Find the end of the value.
        while ((pos < len) && (data[pos] != '"')) {
            // Check for escaping.
            if (data[pos] == '\\') {
                if (pos + 1 >= len) {
                    // A backslash as the last character in the C-D header.
                    part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
                    return HTP_DECLINED;
                }

                // Allow " and \ to be escaped.
                if ((data[pos + 1] == '"')||(data[pos + 1] == '\\')) {
                    // Go over the quoted character.
                    pos++;
                }
            }

            pos++;
        }

        // If we've reached the end of the string that means the
        // value was not terminated properly (the second double quote is missing).
        if (pos == len) {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }

        // Expecting the terminating double quote.
        if (data[pos] != '"') {            
            part->parser->multipart.flags |= HTP_MULTIPART_CD_SYNTAX_INVALID;
            return HTP_DECLINED;
        }

        pos++; // Over the terminating double quote.

        // Finally, process the parameter value.

        switch (param_type) {
            case CD_PARAM_NAME:
                // Check that we have not seen the name parameter already.
                if (part->name != NULL) {                    
                    part->parser->multipart.flags |= HTP_MULTIPART_CD_PARAM_REPEATED;
                    return HTP_DECLINED;
                }
                
                part->name = bstr_dup_mem(data + start, pos - start - 1);
                if (part->name == NULL) return HTP_ERROR;

                htp_mpart_decode_quoted_cd_value_inplace(part->name);

                break;

            case CD_PARAM_FILENAME:                
                // Check that we have not seen the filename parameter already.
                if (part->file != NULL) {                    
                    part->parser->multipart.flags |= HTP_MULTIPART_CD_PARAM_REPEATED;
                    return HTP_DECLINED;
                }
 
                part->file = calloc(1, sizeof (htp_file_t));
                if (part->file == NULL) return HTP_ERROR;

                part->file->fd = -1;
                part->file->source = HTP_FILE_MULTIPART;

                part->file->filename = bstr_dup_mem(data + start, pos - start - 1);
                if (part->file->filename == NULL) {
                    free(part->file);
                    return HTP_ERROR;
                }

                htp_mpart_decode_quoted_cd_value_inplace(part->file->filename);
                
                break;
                
            default:
                // Unknown parameter.                
                part->parser->multipart.flags |= HTP_MULTIPART_CD_PARAM_UNKNOWN;
                return HTP_DECLINED;
                break;
        }       

        // Continue to parse the next parameter, if any.
    }

    return HTP_OK;
}

/**
 * Parses the Content-Type part header, if present.
 *
 * @param[in] part
 * @return HTP_OK on success, HTP_DECLINED if the C-T header is not present, and HTP_ERROR on failure.
 */
static htp_status_t htp_mpart_part_parse_c_t(htp_multipart_part_t *part) {
    htp_header_t *h = (htp_header_t *) htp_table_get_c(part->headers, "content-type");
    if (h == NULL) return HTP_DECLINED;
    return htp_parse_ct_header(h->value, &part->content_type);
}

/**
 * Processes part headers.
 *
 * @param[in] part
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_mpart_part_process_headers(htp_multipart_part_t *part) {
    if (htp_mpart_part_parse_c_d(part) == HTP_ERROR) return HTP_ERROR;
    if (htp_mpart_part_parse_c_t(part) == HTP_ERROR) return HTP_ERROR;

    return HTP_OK;
}

/**
 * Parses one part header.
 *
 * @param[in] part
 * @param[in] data
 * @param[in] len
 * @return HTP_OK on success, HTP_DECLINED on parsing error, HTP_ERROR on fatal error.
 */
htp_status_t htp_mpartp_parse_header(htp_multipart_part_t *part, const unsigned char *data, size_t len) {
    size_t name_start, name_end;
    size_t value_start, value_end;
   
    // We do not allow NUL bytes here.
    if (memchr(data, '\0', len) != NULL) {        
        part->parser->multipart.flags |= HTP_MULTIPART_NUL_BYTE;
        return HTP_DECLINED;
    }

    name_start = 0;

    // Look for the starting position of the name first.
    size_t colon_pos = 0;

    while ((colon_pos < len)&&(htp_is_space(data[colon_pos]))) colon_pos++;
    if (colon_pos != 0) {
        // Whitespace before header name.
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_INVALID;
        return HTP_DECLINED;
    }

    // Now look for the colon.
    while ((colon_pos < len) && (data[colon_pos] != ':')) colon_pos++;

    if (colon_pos == len) {
        // Missing colon.
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_INVALID;
        return HTP_DECLINED;
    }

    if (colon_pos == 0) {
        // Empty header name.
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_INVALID;
        return HTP_DECLINED;
    }

    name_end = colon_pos;

    // Ignore LWS after header name.
    size_t prev = name_end;
    while ((prev > name_start) && (htp_is_lws(data[prev - 1]))) {
        prev--;
        name_end--;

        // LWS after field name. Not allowing for now.
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_INVALID;
        return HTP_DECLINED;
    }

    // Header value.

    value_start = colon_pos + 1;

    // Ignore LWS before value.
    while ((value_start < len) && (htp_is_lws(data[value_start]))) value_start++;

    if (value_start == len) {
        // No header value.
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_INVALID;
        return HTP_DECLINED;
    }   

    // Assume the value is at the end.
    value_end = len;

    // Check that the header name is a token.
    size_t i = name_start;
    while (i < name_end) {
        if (!htp_is_token(data[i])) {
            part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_INVALID;
            return HTP_DECLINED;
        }

        i++;
    }

    // Now extract the name and the value.
    htp_header_t *h = calloc(1, sizeof (htp_header_t));
    if (h == NULL) return HTP_ERROR;

    h->name = bstr_dup_mem(data + name_start, name_end - name_start);
    if (h->name == NULL) {
        free(h);
        return HTP_ERROR;
    }

    h->value = bstr_dup_mem(data + value_start, value_end - value_start);
    if (h->value == NULL) {
        bstr_free(h->name);
        free(h);
        return HTP_ERROR;
    }

    if ((bstr_cmp_c_nocase(h->name, "content-disposition") != 0) && (bstr_cmp_c_nocase(h->name, "content-type") != 0)) {
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_UNKNOWN;
    }

    // Check if the header already exists.
    htp_header_t * h_existing = htp_table_get(part->headers, h->name);
    if (h_existing != NULL) {
        // Add to the existing header.
        bstr *new_value = bstr_expand(h_existing->value, bstr_len(h_existing->value)
                + 2 + bstr_len(h->value));
        if (new_value == NULL) {
            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
            return HTP_ERROR;
        }

        h_existing->value = new_value;
        bstr_add_mem_noex(h_existing->value, ", ", 2);
        bstr_add_noex(h_existing->value, h->value);

        // The header is no longer needed.
        bstr_free(h->name);
        bstr_free(h->value);
        free(h);

        // Keep track of same-name headers.
        h_existing->flags |= HTP_MULTIPART_PART_HEADER_REPEATED;
        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_REPEATED;
    } else {
        // Add as a new header.
        if (htp_table_add(part->headers, h->name, h) != HTP_OK) {
            bstr_free(h->value);
            bstr_free(h->name);
            free(h);
            return HTP_ERROR;
        }
    }

    return HTP_OK;
}

/**
 * Creates a new Multipart part.
 *
 * @param[in] parser
 * @return New part instance, or NULL on memory allocation failure.
 */
htp_multipart_part_t *htp_mpart_part_create(htp_mpartp_t *parser) {
    htp_multipart_part_t * part = calloc(1, sizeof (htp_multipart_part_t));
    if (part == NULL) return NULL;

    part->headers = htp_table_create(4);
    if (part->headers == NULL) {
        free(part);
        return NULL;
    }

    part->parser = parser;
    bstr_builder_clear(parser->part_data_pieces);
    bstr_builder_clear(parser->part_header_pieces);

    return part;
}

/**
 * Destroys a part.
 *
 * @param[in] part
 * @param[in] gave_up_data
 */
void htp_mpart_part_destroy(htp_multipart_part_t *part, int gave_up_data) {
    if (part == NULL) return;

    if (part->file != NULL) {
        bstr_free(part->file->filename);

        if (part->file->tmpname != NULL) {
            unlink(part->file->tmpname);
            free(part->file->tmpname);
        }

        free(part->file);
        part->file = NULL;
    }

    if ((!gave_up_data) || (part->type != MULTIPART_PART_TEXT)) {
        bstr_free(part->name);
        bstr_free(part->value);
    }

    bstr_free(part->content_type);

    if (part->headers != NULL) {
        htp_header_t *h = NULL;
        for (size_t i = 0, n = htp_table_size(part->headers); i < n; i++) {
            h = htp_table_get_index(part->headers, i, NULL);
            bstr_free(h->name);
            bstr_free(h->value);
            free(h);
        }

        htp_table_destroy(part->headers);
    }

    free(part);
}

/**
 * Finalizes part processing.
 *
 * @param[in] part
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_mpart_part_finalize_data(htp_multipart_part_t *part) {
    // Determine if this part is the epilogue.

    if (part->parser->multipart.flags & HTP_MULTIPART_SEEN_LAST_BOUNDARY) {
        if (part->type == MULTIPART_PART_UNKNOWN) {
            // Assume that the unknown part after the last boundary is the epilogue.            
            part->parser->current_part->type = MULTIPART_PART_EPILOGUE;

            // But if we've already seen a part we thought was the epilogue,
            // raise HTP_MULTIPART_PART_UNKNOWN. Multiple epilogues are not allowed.
            if (part->parser->multipart.flags & HTP_MULTIPART_HAS_EPILOGUE) {
                part->parser->multipart.flags |= HTP_MULTIPART_PART_UNKNOWN;
            }

            part->parser->multipart.flags |= HTP_MULTIPART_HAS_EPILOGUE;
        } else {
            part->parser->multipart.flags |= HTP_MULTIPART_PART_AFTER_LAST_BOUNDARY;
        }
    }

    // Sanity checks.

    // Have we seen complete part headers? If we have not, that means that the part ended prematurely.
    if ((part->parser->current_part->type != MULTIPART_PART_EPILOGUE) && (part->parser->current_part_mode != MODE_DATA)) {
        part->parser->multipart.flags |= HTP_MULTIPART_PART_INCOMPLETE;
    }

    // Have we been able to determine the part type? If not, this means
    // that the part did not contain the C-D header.
    if (part->type == MULTIPART_PART_UNKNOWN) {
        part->parser->multipart.flags |= HTP_MULTIPART_PART_UNKNOWN;
    }

    // Finalize part value.   

    if (part->type == MULTIPART_PART_FILE) {
        // Notify callbacks about the end of the file.
        htp_mpartp_run_request_file_data_hook(part, NULL, 0);

        // If we are storing the file to disk, close the file descriptor.
        if (part->file->fd != -1) {
            close(part->file->fd);
        }
    } else {
        // Combine value pieces into a single buffer.
        if (bstr_builder_size(part->parser->part_data_pieces) > 0) {
            part->value = bstr_builder_to_str(part->parser->part_data_pieces);
            bstr_builder_clear(part->parser->part_data_pieces);
        }
    }

    return HTP_OK;
}

htp_status_t htp_mpartp_run_request_file_data_hook(htp_multipart_part_t *part, const unsigned char *data, size_t len) {
    if (part->parser->cfg == NULL) return HTP_OK;

    // Keep track of the file length.
    part->file->len += len;

    // Package data for the callbacks.
    htp_file_data_t file_data;
    file_data.file = part->file;
    file_data.data = data;
    file_data.len = (const size_t) len;

    // Send data to callbacks
    htp_status_t rc = htp_hook_run_all(part->parser->cfg->hook_request_file_data, &file_data);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

/**
 * Handles part data.
 *
 * @param[in] part
 * @param[in] data
 * @param[in] len
 * @param[in] is_line
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
htp_status_t htp_mpart_part_handle_data(htp_multipart_part_t *part, const unsigned char *data, size_t len, int is_line) {
    #if HTP_DEBUG
    fprintf(stderr, "Part type %d mode %d is_line %d\n", part->type, part->parser->current_part_mode, is_line);
    fprint_raw_data(stderr, "htp_mpart_part_handle_data: data chunk", data, len);
    #endif

    // Keep track of raw part length.
    part->len += len;

    // If we're processing a part that came after the last boundary, then we're not sure if it
    // is the epilogue part or some other part (in case of evasion attempt). For that reason we
    // will keep all its data in the part_data_pieces structure. If it ends up not being the
    // epilogue, this structure will be cleared.
    if ((part->parser->multipart.flags & HTP_MULTIPART_SEEN_LAST_BOUNDARY) && (part->type == MULTIPART_PART_UNKNOWN)) {
        bstr_builder_append_mem(part->parser->part_data_pieces, data, len);
    }

    if (part->parser->current_part_mode == MODE_LINE) {
        // Line mode.       

        if (is_line) {
            // End of the line.

            bstr *line = NULL;

            // If this line came to us in pieces, combine them now into a single buffer.
            if (bstr_builder_size(part->parser->part_header_pieces) > 0) {
                bstr_builder_append_mem(part->parser->part_header_pieces, data, len);
                line = bstr_builder_to_str(part->parser->part_header_pieces);
                if (line == NULL) return HTP_ERROR;
                bstr_builder_clear(part->parser->part_header_pieces);

                data = bstr_ptr(line);
                len = bstr_len(line);
            }

            // Ignore the line endings.
            if (len > 1) {
                if (data[len - 1] == LF) len--;
                if (data[len - 1] == CR) len--;
            } else if (len > 0) {
                if (data[len - 1] == LF) len--;
            }

            // Is it an empty line?
            if (len == 0) {
                // Empty line; process headers and switch to data mode.

                // Process the pending header, if any.
                if (part->parser->pending_header_line != NULL) {
                    if (htp_mpartp_parse_header(part, bstr_ptr(part->parser->pending_header_line),
                            bstr_len(part->parser->pending_header_line)) == HTP_ERROR)
                    {
                        bstr_free(line);
                        return HTP_ERROR;
                    }

                    bstr_free(part->parser->pending_header_line);
                    part->parser->pending_header_line = NULL;
                }

                if (htp_mpart_part_process_headers(part) == HTP_ERROR) {
                    bstr_free(line);
                    return HTP_ERROR;
                }

                part->parser->current_part_mode = MODE_DATA;
                bstr_builder_clear(part->parser->part_header_pieces);

                if (part->file != NULL) {
                    // Changing part type because we have a filename.
                    part->type = MULTIPART_PART_FILE;

                    if ((part->parser->extract_files) && (part->parser->file_count < part->parser->extract_limit)) {
                        char buf[255];
                        
                        strncpy(buf, part->parser->extract_dir, 254);
                        strncat(buf, "/libhtp-multipart-file-XXXXXX", 254 - strlen(buf));

                        part->file->tmpname = strdup(buf);
                        if (part->file->tmpname == NULL) {
                            bstr_free(line);
                            return HTP_ERROR;
                        }

                        mode_t previous_mask = umask(S_IXUSR | S_IRWXG | S_IRWXO);
                        part->file->fd = mkstemp(part->file->tmpname);
                        umask(previous_mask);

                        if (part->file->fd < 0) {
                            bstr_free(line);
                            return HTP_ERROR;
                        }

                        part->parser->file_count++;
                    }
                } else if (part->name != NULL) {
                    // Changing part type because we have a name.
                    part->type = MULTIPART_PART_TEXT;
                    bstr_builder_clear(part->parser->part_data_pieces);
                } else {
                    // Do nothing; the type stays MULTIPART_PART_UNKNOWN.
                }
            } else {
                // Not an empty line.

                // Is there a pending header?
                if (part->parser->pending_header_line == NULL) {
                    if (line != NULL) {
                        part->parser->pending_header_line = line;
                        line = NULL;
                    } else {
                        part->parser->pending_header_line = bstr_dup_mem(data, len);
                        if (part->parser->pending_header_line == NULL) return HTP_ERROR;
                    }
                } else {
                    // Is this a folded line?
                    if (isspace(data[0])) {
                        // Folding; add to the existing line.
                        part->parser->multipart.flags |= HTP_MULTIPART_PART_HEADER_FOLDING;
                        part->parser->pending_header_line = bstr_add_mem(part->parser->pending_header_line, data, len);
                        if (part->parser->pending_header_line == NULL) {
                            bstr_free(line);
                            return HTP_ERROR;
                        }
                    } else {
                        // Process the pending header line.                        
                        if (htp_mpartp_parse_header(part, bstr_ptr(part->parser->pending_header_line),
                                bstr_len(part->parser->pending_header_line)) == HTP_ERROR)
                        {
                            bstr_free(line);
                            return HTP_ERROR;
                        }
                        
                        bstr_free(part->parser->pending_header_line);

                        if (line != NULL) {
                            part->parser->pending_header_line = line;
                            line = NULL;
                        } else {
                            part->parser->pending_header_line = bstr_dup_mem(data, len);
                            if (part->parser->pending_header_line == NULL) return HTP_ERROR;
                        }
                    }
                }
            }

            bstr_free(line);
            line = NULL;
        } else {
            // Not end of line; keep the data chunk for later.
            bstr_builder_append_mem(part->parser->part_header_pieces, data, len);
        }
    } else {
        // Data mode; keep the data chunk for later (but not if it is a file).
        switch (part->type) {
            case MULTIPART_PART_EPILOGUE:
            case MULTIPART_PART_PREAMBLE:
            case MULTIPART_PART_TEXT:
            case MULTIPART_PART_UNKNOWN:
                // Make a copy of the data in RAM.
                bstr_builder_append_mem(part->parser->part_data_pieces, data, len);
                break;

            case MULTIPART_PART_FILE:
                // Invoke file data callbacks.
                htp_mpartp_run_request_file_data_hook(part, data, len);

                // Optionally, store the data in a file.
                if (part->file->fd != -1) {
                    if (write(part->file->fd, data, len) < 0) {
                        return HTP_ERROR;
                    }
                }
                break;
                
            default:
                // Internal error.
                return HTP_ERROR;
                break;
        }
    }

    return HTP_OK;
}

/**
 * Handles data, creating new parts as necessary.
 *
 * @param[in] mpartp
 * @param[in] data
 * @param[in] len
 * @param[in] is_line
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
static htp_status_t htp_mpartp_handle_data(htp_mpartp_t *parser, const unsigned char *data, size_t len, int is_line) {
    if (len == 0) return HTP_OK;

    // Do we have a part already?
    if (parser->current_part == NULL) {
        // Create a new part.
        parser->current_part = htp_mpart_part_create(parser);
        if (parser->current_part == NULL) return HTP_ERROR;

        if (parser->multipart.boundary_count == 0) {
            // We haven't seen a boundary yet, so this must be the preamble part.
            parser->current_part->type = MULTIPART_PART_PREAMBLE;
            parser->multipart.flags |= HTP_MULTIPART_HAS_PREAMBLE;
            parser->current_part_mode = MODE_DATA;
        } else {
            // Part after preamble.
            parser->current_part_mode = MODE_LINE;
        }

        // Add part to the list.        
        htp_list_push(parser->multipart.parts, parser->current_part);

        #ifdef HTP_DEBUG
        fprintf(stderr, "Created new part type %d\n", parser->current_part->type);
        #endif
    }

    // Send data to the part.
    return htp_mpart_part_handle_data(parser->current_part, data, len, is_line);
}

/**
 * Handles a boundary event, which means that it will finalize a part if one exists.
 *
 * @param[in] mpartp
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
static htp_status_t htp_mpartp_handle_boundary(htp_mpartp_t *parser) {
    #if HTP_DEBUG
    fprintf(stderr, "htp_mpartp_handle_boundary\n");
    #endif

    if (parser->current_part != NULL) {
        if (htp_mpart_part_finalize_data(parser->current_part) != HTP_OK) {
            return HTP_ERROR;
        }

        // We're done with this part
        parser->current_part = NULL;

        // Revert to line mode
        parser->current_part_mode = MODE_LINE;
    }

    return HTP_OK;
}

static htp_status_t htp_mpartp_init_boundary(htp_mpartp_t *parser, unsigned char *data, size_t len) {
    if ((parser == NULL) || (data == NULL)) return HTP_ERROR;

    // Copy the boundary and convert it to lowercase.

    parser->multipart.boundary_len = len + 4;
    parser->multipart.boundary = malloc(parser->multipart.boundary_len + 1);
    if (parser->multipart.boundary == NULL) return HTP_ERROR;

    parser->multipart.boundary[0] = CR;
    parser->multipart.boundary[1] = LF;
    parser->multipart.boundary[2] = '-';
    parser->multipart.boundary[3] = '-';

    for (size_t i = 0; i < len; i++) {
        parser->multipart.boundary[i + 4] = data[i];
    }

    parser->multipart.boundary[parser->multipart.boundary_len] = '\0';

    // We're starting in boundary-matching mode. The first boundary can appear without the
    // CRLF, and our starting state expects that. If we encounter non-boundary data, the
    // state will switch to data mode. Then, if the data is CRLF or LF, we will go back
    // to boundary matching. Thus, we handle all the possibilities.

    parser->parser_state = STATE_BOUNDARY;
    parser->boundary_match_pos = 2;

    return HTP_OK;
}

htp_mpartp_t *htp_mpartp_create(htp_cfg_t *cfg, bstr *boundary, uint64_t flags) {
    if ((cfg == NULL) || (boundary == NULL)) return NULL;

    htp_mpartp_t *parser = calloc(1, sizeof (htp_mpartp_t));
    if (parser == NULL) return NULL;

    parser->cfg = cfg;

    parser->boundary_pieces = bstr_builder_create();
    if (parser->boundary_pieces == NULL) {
        htp_mpartp_destroy(parser);
        return NULL;
    }

    parser->part_data_pieces = bstr_builder_create();
    if (parser->part_data_pieces == NULL) {
        htp_mpartp_destroy(parser);
        return NULL;
    }

    parser->part_header_pieces = bstr_builder_create();
    if (parser->part_header_pieces == NULL) {
        htp_mpartp_destroy(parser);
        return NULL;
    }

    parser->multipart.parts = htp_list_create(64);
    if (parser->multipart.parts == NULL) {
        htp_mpartp_destroy(parser);
        return NULL;
    }

    parser->multipart.flags = flags;
    parser->parser_state = STATE_INIT;
    parser->extract_files = cfg->extract_request_files;
    parser->extract_dir = cfg->tmpdir;
    if (cfg->extract_request_files_limit >= 0) {
        parser->extract_limit = cfg->extract_request_files_limit;
    } else {
        parser->extract_limit = DEFAULT_FILE_EXTRACT_LIMIT;
    }
    parser->handle_data = htp_mpartp_handle_data;
    parser->handle_boundary = htp_mpartp_handle_boundary;

    // Initialize the boundary.
    htp_status_t rc = htp_mpartp_init_boundary(parser, bstr_ptr(boundary), bstr_len(boundary));
    if (rc != HTP_OK) {
        htp_mpartp_destroy(parser);
        return NULL;
    }

    // On success, the ownership of the boundary parameter
    // is transferred to us. We made a copy, and so we
    // don't need it any more.
    bstr_free(boundary);

    return parser;
}

void htp_mpartp_destroy(htp_mpartp_t *parser) {
    if (parser == NULL) return;

    if (parser->multipart.boundary != NULL) {
        free(parser->multipart.boundary);
    }

    bstr_builder_destroy(parser->boundary_pieces);
    bstr_builder_destroy(parser->part_header_pieces);
    bstr_free(parser->pending_header_line);
    bstr_builder_destroy(parser->part_data_pieces);

    // Free the parts.
    if (parser->multipart.parts != NULL) {
        for (size_t i = 0, n = htp_list_size(parser->multipart.parts); i < n; i++) {
            htp_multipart_part_t * part = htp_list_get(parser->multipart.parts, i);
            htp_mpart_part_destroy(part, parser->gave_up_data);
        }

        htp_list_destroy(parser->multipart.parts);
    }

    free(parser);
}

/**
 * Processes set-aside data.
 *
 * @param[in] mpartp
 * @param[in] data
 * @param[in] pos
 * @param[in] startpos
 * @param[in] return_pos
 * @param[in] matched
 * @return HTP_OK on success, HTP_ERROR on failure.
 */
static htp_status_t htp_martp_process_aside(htp_mpartp_t *parser, int matched) {
    // The stored data pieces can contain up to one line. If we're in data mode and there
    // was no boundary match, things are straightforward -- we process everything as data.
    // If there was a match, we need to take care to not send the line ending as data, nor
    // anything that follows (because it's going to be a part of the boundary). Similarly,
    // when we are in line mode, we need to split the first data chunk, processing the first
    // part as line and the second part as data.

    #ifdef HTP_DEBUG
    fprintf(stderr, "mpartp_process_aside matched %d current_part_mode %d\n", matched, parser->current_part_mode);
    #endif

    // Do we need to do any chunk splitting?
    if (matched || (parser->current_part_mode == MODE_LINE)) {
        // Line mode or boundary match

        // Process the CR byte, if set aside.
        if ((!matched) && (parser->cr_aside)) {
            // Treat as part data, when there is not a match.
            parser->handle_data(parser, (unsigned char *) &"\r", 1, /* not a line */ 0);
            parser->cr_aside = 0;
        } else {
            // Treat as boundary, when there is a match.
            parser->cr_aside = 0;
        }

        // We know that we went to match a boundary because
        // we saw a new line. Now we have to find that line and
        // process it. It's either going to be in the current chunk,
        // or in the first stored chunk.
        if (bstr_builder_size(parser->boundary_pieces) > 0) {
            int first = 1;
            for (size_t i = 0, n = htp_list_size(parser->boundary_pieces->pieces); i < n; i++) {
                bstr *b = htp_list_get(parser->boundary_pieces->pieces, i);

                if (first) {
                    first = 0;

                    // Split the first chunk.

                    if (!matched) {
                        // In line mode, we are OK with line endings.
                        parser->handle_data(parser, bstr_ptr(b), parser->boundary_candidate_pos, /* line */ 1);
                    } else {
                        // But if there was a match, the line ending belongs to the boundary.
                        unsigned char *dx = bstr_ptr(b);
                        size_t lx = parser->boundary_candidate_pos;

                        // Remove LF or CRLF.
                        if ((lx > 0) && (dx[lx - 1] == LF)) {
                            lx--;
                            // Remove CR.
                            if ((lx > 0) && (dx[lx - 1] == CR)) {
                                lx--;
                            }
                        }

                        parser->handle_data(parser, dx, lx, /* not a line */ 0);
                    }

                    // The second part of the split chunks belongs to the boundary
                    // when matched, data otherwise.
                    if (!matched) {
                        parser->handle_data(parser, bstr_ptr(b) + parser->boundary_candidate_pos,
                                bstr_len(b) - parser->boundary_candidate_pos, /* not a line */ 0);
                    }
                } else {
                    // Do not send data if there was a boundary match. The stored
                    // data belongs to the boundary.
                    if (!matched) {
                        parser->handle_data(parser, bstr_ptr(b), bstr_len(b), /* not a line */ 0);
                    }
                }
            }

            bstr_builder_clear(parser->boundary_pieces);
        }
    } else {
        // Data mode and no match.       

        // In data mode, we process the lone CR byte as data.
        if (parser->cr_aside) {
            parser->handle_data(parser, (const unsigned char *)&"\r", 1, /* not a line */ 0);
            parser->cr_aside = 0;
        }

        // We then process any pieces that we might have stored, also as data.
        if (bstr_builder_size(parser->boundary_pieces) > 0) {
            for (size_t i = 0, n = htp_list_size(parser->boundary_pieces->pieces); i < n; i++) {
                bstr *b = htp_list_get(parser->boundary_pieces->pieces, i);
                parser->handle_data(parser, bstr_ptr(b), bstr_len(b), /* not a line */ 0);
            }

            bstr_builder_clear(parser->boundary_pieces);
        }
    }

    return HTP_OK;
}

htp_status_t htp_mpartp_finalize(htp_mpartp_t *parser) {
    if (parser->current_part != NULL) {
        // Process buffered data, if any.
        htp_martp_process_aside(parser, 0);

        // Finalize the last part.
        if (htp_mpart_part_finalize_data(parser->current_part) != HTP_OK) return HTP_ERROR;

        // It is OK to end abruptly in the epilogue part, but not in any other.
        if (parser->current_part->type != MULTIPART_PART_EPILOGUE) {
            parser->multipart.flags |= HTP_MULTIPART_INCOMPLETE;
        }
    }

    bstr_builder_clear(parser->boundary_pieces);

    return HTP_OK;
}

htp_status_t htp_mpartp_parse(htp_mpartp_t *parser, const void *_data, size_t len) {
    unsigned char *data = (unsigned char *) _data;

    // The current position in the entire input buffer.
    size_t pos = 0;

    // The position of the first unprocessed byte of data. We split the
    // input buffer into smaller chunks, according to their purpose. Once
    // an entire such smaller chunk is processed, we move to the next
    // and update startpos.
    size_t startpos = 0;

    // The position of the (possible) boundary. We investigate for possible
    // boundaries whenever we encounter CRLF or just LF. If we don't find a
    // boundary we need to go back, and this is what data_return_pos helps with.
    size_t data_return_pos = 0;

    #if HTP_DEBUG
    fprint_raw_data(stderr, "htp_mpartp_parse: data chunk", data, len);
    #endif

    // While there's data in the input buffer.

    while (pos < len) {

STATE_SWITCH:
        #if HTP_DEBUG        
        fprintf(stderr, "htp_mpartp_parse: state %d pos %zd startpos %zd\n", parser->parser_state, pos, startpos);
        #endif

        switch (parser->parser_state) {

            case STATE_INIT:
                // Incomplete initialization.
                return HTP_ERROR;
                break;

            case STATE_DATA: // Handle part data.

                // While there's data in the input buffer.

                while (pos < len) {
                    // Check for a CRLF-terminated line.
                    if (data[pos] == CR) {
                        // We have a CR byte.

                        // Is this CR the last byte in the input buffer?
                        if (pos + 1 == len) {
                            // We have CR as the last byte in input. We are going to process
                            // what we have in the buffer as data, except for the CR byte,
                            // which we're going to leave for later. If it happens that a
                            // CR is followed by a LF and then a boundary, the CR is going
                            // to be discarded.
                            pos++; // Advance over CR.
                            parser->cr_aside = 1;
                        } else {
                            // We have CR and at least one more byte in the buffer, so we
                            // are able to test for the LF byte too.
                            if (data[pos + 1] == LF) {
                                pos += 2; // Advance over CR and LF.

                                parser->multipart.flags |= HTP_MULTIPART_CRLF_LINE;

                                // Prepare to switch to boundary testing.
                                data_return_pos = pos;
                                parser->boundary_candidate_pos = pos - startpos;
                                parser->boundary_match_pos = 2; // After LF; position of the first dash.
                                parser->parser_state = STATE_BOUNDARY;

                                goto STATE_SWITCH;
                            } else {
                                // This is not a new line; advance over the
                                // byte and clear the CR set-aside flag.
                                pos++;
                                parser->cr_aside = 0;
                            }
                        }
                    } else if (data[pos] == LF) { // Check for a LF-terminated line.
                        pos++; // Advance over LF.

                        // Did we have a CR in the previous input chunk?
                        if (parser->cr_aside == 0) {
                            parser->multipart.flags |= HTP_MULTIPART_LF_LINE;
                        } else {
                            parser->multipart.flags |= HTP_MULTIPART_CRLF_LINE;
                        }

                        // Prepare to switch to boundary testing.
                        data_return_pos = pos;
                        parser->boundary_candidate_pos = pos - startpos;
                        parser->boundary_match_pos = 2; // After LF; position of the first dash.
                        parser->parser_state = STATE_BOUNDARY;

                        goto STATE_SWITCH;
                    } else {
                        // Take one byte from input
                        pos++;

                        // Earlier we might have set aside a CR byte not knowing if the next
                        // byte is a LF. Now we know that it is not, and so we can release the CR.
                        if (parser->cr_aside) {
                            parser->handle_data(parser, (unsigned char *) &"\r", 1, /* not a line */ 0);
                            parser->cr_aside = 0;
                        }
                    }
                } // while               

                // No more data in the input buffer; process the data chunk.
                parser->handle_data(parser, data + startpos, pos - startpos - parser->cr_aside, /* not a line */ 0);

                break;

            case STATE_BOUNDARY: // Handle a possible boundary.
                while (pos < len) {
                    #ifdef HTP_DEBUG
                    fprintf(stderr, "boundary (len %zd pos %zd char %d) data char %d\n", parser->multipart.boundary_len,
                            parser->boundary_match_pos, parser->multipart.boundary[parser->boundary_match_pos], tolower(data[pos]));
                    #endif                   

                    // Check if the bytes match.
                    if (!(data[pos] == parser->multipart.boundary[parser->boundary_match_pos])) {
                        // Boundary mismatch.

                        // Process stored (buffered) data.
                        htp_martp_process_aside(parser, /* no match */ 0);

                        // Return back where data parsing left off.
                        if (parser->current_part_mode == MODE_LINE) {
                            // In line mode, we process the line.
                            parser->handle_data(parser, data + startpos, data_return_pos - startpos, /* line */ 1);
                            startpos = data_return_pos;
                        } else {
                            // In data mode, we go back where we left off.
                            pos = data_return_pos;
                        }

                        parser->parser_state = STATE_DATA;

                        goto STATE_SWITCH;
                    }

                    // Consume one matched boundary byte
                    pos++;
                    parser->boundary_match_pos++;

                    // Have we seen all boundary bytes?
                    if (parser->boundary_match_pos == parser->multipart.boundary_len) {
                        // Boundary match!

                        // Process stored (buffered) data.
                        htp_martp_process_aside(parser, /* boundary match */ 1);

                        // Process data prior to the boundary in the current input buffer.
                        // Because we know this is the last chunk before boundary, we can
                        // remove the line endings.
                        size_t dlen = data_return_pos - startpos;
                        if ((dlen > 0) && (data[startpos + dlen - 1] == LF)) dlen--;
                        if ((dlen > 0) && (data[startpos + dlen - 1] == CR)) dlen--;
                        parser->handle_data(parser, data + startpos, dlen, /* line */ 1);

                        // Keep track of how many boundaries we've seen.
                        parser->multipart.boundary_count++;

                        if (parser->multipart.flags & HTP_MULTIPART_SEEN_LAST_BOUNDARY) {
                            parser->multipart.flags |= HTP_MULTIPART_PART_AFTER_LAST_BOUNDARY;
                        }

                        // Run boundary match.
                        parser->handle_boundary(parser);

                        // We now need to check if this is the last boundary in the payload
                        parser->parser_state = STATE_BOUNDARY_IS_LAST2;

                        goto STATE_SWITCH;
                    }
                } // while

                // No more data in the input buffer; store (buffer) the unprocessed
                // part for later, for after we find out if this is a boundary.
                bstr_builder_append_mem(parser->boundary_pieces, data + startpos, len - startpos);

                break;

            case STATE_BOUNDARY_IS_LAST2:
                // Examine the first byte after the last boundary character. If it is
                // a dash, then we maybe processing the last boundary in the payload. If
                // it is not, move to eat all bytes until the end of the line.

                if (data[pos] == '-') {
                    // Found one dash, now go to check the next position.
                    pos++;
                    parser->parser_state = STATE_BOUNDARY_IS_LAST1;
                } else {
                    // This is not the last boundary. Change state but
                    // do not advance the position, allowing the next
                    // state to process the byte.
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                }
                break;

            case STATE_BOUNDARY_IS_LAST1:
                // Examine the byte after the first dash; expected to be another dash.
                // If not, eat all bytes until the end of the line.

                if (data[pos] == '-') {
                    // This is indeed the last boundary in the payload.
                    pos++;
                    parser->multipart.flags |= HTP_MULTIPART_SEEN_LAST_BOUNDARY;
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                } else {
                    // The second character is not a dash, and so this is not
                    // the final boundary. Raise the flag for the first dash,
                    // and change state to consume the rest of the boundary line.
                    parser->multipart.flags |= HTP_MULTIPART_BBOUNDARY_NLWS_AFTER;
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                }
                break;

            case STATE_BOUNDARY_EAT_LWS:
                if (data[pos] == CR) {
                    // CR byte, which could indicate a CRLF line ending.
                    pos++;
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS_CR;
                } else if (data[pos] == LF) {
                    // LF line ending; we're done with boundary processing; data bytes follow.
                    pos++;
                    startpos = pos;
                    parser->multipart.flags |= HTP_MULTIPART_LF_LINE;
                    parser->parser_state = STATE_DATA;
                } else {
                    if (htp_is_lws(data[pos])) {
                        // Linear white space is allowed here.
                        parser->multipart.flags |= HTP_MULTIPART_BBOUNDARY_LWS_AFTER;
                        pos++;
                    } else {
                        // Unexpected byte; consume, but remain in the same state.
                        parser->multipart.flags |= HTP_MULTIPART_BBOUNDARY_NLWS_AFTER;
                        pos++;
                    }
                }
                break;

            case STATE_BOUNDARY_EAT_LWS_CR:
                if (data[pos] == LF) {
                    // CRLF line ending; we're done with boundary processing; data bytes follow.
                    pos++;
                    startpos = pos;
                    parser->multipart.flags |= HTP_MULTIPART_CRLF_LINE;
                    parser->parser_state = STATE_DATA;
                } else {
                    // Not a line ending; start again, but do not process this byte.
                    parser->multipart.flags |= HTP_MULTIPART_BBOUNDARY_NLWS_AFTER;
                    parser->parser_state = STATE_BOUNDARY_EAT_LWS;
                }
                break;
        } // switch
    }

    return HTP_OK;
}

static void htp_mpartp_validate_boundary(bstr *boundary, uint64_t *flags) {
    /*

    RFC 1341:

    The only mandatory parameter for the multipart  Content-Type
    is  the  boundary  parameter,  which  consists  of  1  to 70
    characters from a set of characters known to be very  robust
    through  email  gateways,  and  NOT ending with white space.
    (If a boundary appears to end with white  space,  the  white
    space  must be presumed to have been added by a gateway, and
    should  be  deleted.)   It  is  formally  specified  by  the
    following BNF:

    boundary := 0*69<bchars> bcharsnospace

    bchars := bcharsnospace / " "

    bcharsnospace :=    DIGIT / ALPHA / "'" / "(" / ")" / "+" / "_"
                          / "," / "-" / "." / "/" / ":" / "=" / "?"
     */

    /*
     Chrome: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryT4AfwQCOgIxNVwlD
    Firefox: Content-Type: multipart/form-data; boundary=---------------------------21071316483088
       MSIE: Content-Type: multipart/form-data; boundary=---------------------------7dd13e11c0452
      Opera: Content-Type: multipart/form-data; boundary=----------2JL5oh7QWEDwyBllIRc7fh
     Safari: Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryre6zL3b0BelnTY5S
     */

    unsigned char *data = bstr_ptr(boundary);
    size_t len = bstr_len(boundary);

    // The RFC allows up to 70 characters. In real life,
    // boundaries tend to be shorter.
    if ((len == 0) || (len > 70)) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    }

    // Check boundary characters. This check is stricter than the
    // RFC, which seems to allow many separator characters.
    size_t pos = 0;
    while (pos < len) {
        if (!(((data[pos] >= '0') && (data[pos] <= '9'))
                || ((data[pos] >= 'a') && (data[pos] <= 'z'))
                || ((data[pos] >= 'A') && (data[pos] <= 'Z'))
                || (data[pos] == '-'))) {

            switch (data[pos]) {
                case '\'':
                case '(':
                case ')':
                case '+':
                case '_':
                case ',':
                case '.':
                case '/':
                case ':':
                case '=':
                case '?':
                    // These characters are allowed by the RFC, but not common.
                    *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
                    break;
                    
                default:
                    // Invalid character.
                    *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
                    break;
            }
        }

        pos++;
    }
}

static void htp_mpartp_validate_content_type(bstr *content_type, uint64_t *flags) {
    unsigned char *data = bstr_ptr(content_type);
    size_t len = bstr_len(content_type);
    size_t counter = 0;

    while (len > 0) {
        int i = bstr_util_mem_index_of_c_nocase(data, len, "boundary");
        if (i == -1) break;

        data = data + i;
        len = len - i;

        // In order to work around the fact that WebKit actually uses
        // the word "boundary" in their boundary, we also require one
        // equals character the follow the words.
        // "multipart/form-data; boundary=----WebKitFormBoundaryT4AfwQCOgIxNVwlD"
        if (memchr(data, '=', len) == NULL) break;

        counter++;

        // Check for case variations.        
        for (size_t j = 0; j < 8; j++) {
            if (!((*data >= 'a') && (*data <= 'z'))) {
                *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
            }

            data++;
            len--;
        }
    }

    // How many boundaries have we seen?
    if (counter > 1) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    }
}

htp_status_t htp_mpartp_find_boundary(bstr *content_type, bstr **boundary, uint64_t *flags) {
    if ((content_type == NULL) || (boundary == NULL) || (flags == NULL)) return HTP_ERROR;

    // Our approach is to ignore the MIME type and instead just look for
    // the boundary. This approach is more reliable in the face of various
    // evasion techniques that focus on submitting invalid MIME types.

    // Reset flags.
    *flags = 0;

    // Look for the boundary, case insensitive.
    int i = bstr_index_of_c_nocase(content_type, "boundary");
    if (i == -1) return HTP_DECLINED;

    unsigned char *data = bstr_ptr(content_type) + i + 8;
    size_t len = bstr_len(content_type) - i - 8;

    // Look for the boundary value.
    size_t pos = 0;
    while ((pos < len) && (data[pos] != '=')) {
        if (htp_is_space(data[pos])) {
            // It is unusual to see whitespace before the equals sign.
            *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
        } else {
            // But seeing a non-whitespace character may indicate evasion.
            *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        }

        pos++;
    }

    if (pos >= len) {
        // No equals sign in the header.
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        return HTP_DECLINED;
    }

    // Go over the '=' character.
    pos++;

    // Ignore any whitespace after the equals sign.
    while ((pos < len) && (htp_is_space(data[pos]))) {
        if (htp_is_space(data[pos])) {
            // It is unusual to see whitespace after
            // the equals sign.
            *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
        }

        pos++;
    }

    if (pos >= len) {
        // No value after the equals sign.
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        return HTP_DECLINED;
    }

    if (data[pos] == '"') {
        // Quoted boundary.

        // Possibly not very unusual, but let's see.
        *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;

        pos++; // Over the double quote.
        size_t startpos = pos; // Starting position of the boundary.

        // Look for the terminating double quote.
        while ((pos < len) && (data[pos] != '"')) pos++;

        if (pos >= len) {
            // Ran out of space without seeing
            // the terminating double quote.
            *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;

            // Include the starting double quote in the boundary.
            startpos--;
        }

        *boundary = bstr_dup_mem(data + startpos, pos - startpos);
        if (*boundary == NULL) return HTP_ERROR;

        pos++; // Over the double quote.
    } else {
        // Boundary not quoted.

        size_t startpos = pos;

        // Find the end of the boundary. For the time being, we replicate
        // the behavior of PHP 5.4.x. This may result with a boundary that's
        // closer to what would be accepted in real life. Our subsequent
        // checks of boundary characters will catch irregularities.
        while ((pos < len) && (data[pos] != ',') && (data[pos] != ';') && (!htp_is_space(data[pos]))) pos++;

        *boundary = bstr_dup_mem(data + startpos, pos - startpos);
        if (*boundary == NULL) return HTP_ERROR;
    }

    // Check for a zero-length boundary.
    if (bstr_len(*boundary) == 0) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
        bstr_free(*boundary);
        *boundary = NULL;
        return HTP_DECLINED;
    }

    // Allow only whitespace characters after the boundary.
    int seen_space = 0, seen_non_space = 0;

    while (pos < len) {
        if (!htp_is_space(data[pos])) {
            seen_non_space = 1;
        } else {
            seen_space = 1;
        }

        pos++;
    }

    // Raise INVALID if we see any non-space characters,
    // but raise UNUSUAL if we see _only_ space characters.
    if (seen_non_space) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    } else if (seen_space) {
        *flags |= HTP_MULTIPART_HBOUNDARY_UNUSUAL;
    }

    #ifdef HTP_DEBUG
    fprint_bstr(stderr, "Multipart boundary", *boundary);
    #endif   

    // Validate boundary characters.
    htp_mpartp_validate_boundary(*boundary, flags);

    // Correlate with the MIME type. This might be a tad too
    // sensitive because it may catch non-browser access with sloppy
    // implementations, but let's go with it for now.    
    if (bstr_begins_with_c(content_type, "multipart/form-data;") == 0) {
        *flags |= HTP_MULTIPART_HBOUNDARY_INVALID;
    }

    htp_mpartp_validate_content_type(content_type, flags);

    return HTP_OK;
}
