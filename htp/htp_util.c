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
 * Is character a linear white space character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int htp_is_lws(int c) {
    if ((c == ' ') || (c == '\t')) return 1;
    else return 0;
}

/**
 * Is character a separator character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int htp_is_separator(int c) {
    /* separators = "(" | ")" | "<" | ">" | "@"
                  | "," | ";" | ":" | "\" | <">
                  | "/" | "[" | "]" | "?" | "="
                  | "{" | "}" | SP | HT         */
    switch (c) {
        case '(':
        case ')':
        case '<':
        case '>':
        case '@':
        case ',':
        case ';':
        case ':':
        case '\\':
        case '"':
        case '/':
        case '[':
        case ']':
        case '?':
        case '=':
        case '{':
        case '}':
        case ' ':
        case '\t':
            return 1;
            break;
        default:
            return 0;
    }
}

/**
 * Is character a text character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int htp_is_text(int c) {
    if (c == '\t') return 1;
    if (c < 32) return 0;
    return 1;
}

/**
 * Is character a token character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int htp_is_token(int c) {
    /* token = 1*<any CHAR except CTLs or separators> */
    /* CHAR  = <any US-ASCII character (octets 0 - 127)> */
    if ((c < 32) || (c > 126)) return 0;
    if (htp_is_separator(c)) return 0;
    return 1;
}

/**
 * Remove all line terminators (LF or CRLF) from
 * the end of the line provided as input.
 *
 * @return 0 if nothing was removed, 1 if one or more LF characters were removed, or
 *         2 if one or more CR and/or LF characters were removed.
 */
int htp_chomp(unsigned char *data, size_t *len) {
    int r = 0;

    // Loop until there's no more stuff in the buffer
    while (*len > 0) {
        // Try one LF first
        if (data[*len - 1] == LF) {
            (*len)--;
            r = 1;

            if (*len == 0) return r;

            // A CR is allowed before LF
            if (data[*len - 1] == CR) {
                (*len)--;
                r = 2;
            }
        } else return r;
    }

    return r;
}

/**
 * Is character a white space character?
 *
 * @param[in] c
 * @return 0 or 1
 */
int htp_is_space(int c) {
    switch (c) {
        case ' ':
        case '\f':
        case '\v':
        case '\t':
        case '\r':
        case '\n':
            return 1;
        default:
            return 0;
    }
}

/**
 * Converts request method, given as a string, into a number.
 *
 * @param[in] method
 * @return Method number of M_UNKNOWN
 */
int htp_convert_method_to_number(bstr *method) {
    if (method == NULL) return HTP_M_UNKNOWN;

    // TODO Optimize using parallel matching, or something similar.

    if (bstr_cmp_c(method, "GET") == 0) return HTP_M_GET;
    if (bstr_cmp_c(method, "PUT") == 0) return HTP_M_PUT;
    if (bstr_cmp_c(method, "POST") == 0) return HTP_M_POST;
    if (bstr_cmp_c(method, "DELETE") == 0) return HTP_M_DELETE;
    if (bstr_cmp_c(method, "CONNECT") == 0) return HTP_M_CONNECT;
    if (bstr_cmp_c(method, "OPTIONS") == 0) return HTP_M_OPTIONS;
    if (bstr_cmp_c(method, "TRACE") == 0) return HTP_M_TRACE;
    if (bstr_cmp_c(method, "PATCH") == 0) return HTP_M_PATCH;
    if (bstr_cmp_c(method, "PROPFIND") == 0) return HTP_M_PROPFIND;
    if (bstr_cmp_c(method, "PROPPATCH") == 0) return HTP_M_PROPPATCH;
    if (bstr_cmp_c(method, "MKCOL") == 0) return HTP_M_MKCOL;
    if (bstr_cmp_c(method, "COPY") == 0) return HTP_M_COPY;
    if (bstr_cmp_c(method, "MOVE") == 0) return HTP_M_MOVE;
    if (bstr_cmp_c(method, "LOCK") == 0) return HTP_M_LOCK;
    if (bstr_cmp_c(method, "UNLOCK") == 0) return HTP_M_UNLOCK;
    if (bstr_cmp_c(method, "VERSION-CONTROL") == 0) return HTP_M_VERSION_CONTROL;
    if (bstr_cmp_c(method, "CHECKOUT") == 0) return HTP_M_CHECKOUT;
    if (bstr_cmp_c(method, "UNCHECKOUT") == 0) return HTP_M_UNCHECKOUT;
    if (bstr_cmp_c(method, "CHECKIN") == 0) return HTP_M_CHECKIN;
    if (bstr_cmp_c(method, "UPDATE") == 0) return HTP_M_UPDATE;
    if (bstr_cmp_c(method, "LABEL") == 0) return HTP_M_LABEL;
    if (bstr_cmp_c(method, "REPORT") == 0) return HTP_M_REPORT;
    if (bstr_cmp_c(method, "MKWORKSPACE") == 0) return HTP_M_MKWORKSPACE;
    if (bstr_cmp_c(method, "MKACTIVITY") == 0) return HTP_M_MKACTIVITY;
    if (bstr_cmp_c(method, "BASELINE-CONTROL") == 0) return HTP_M_BASELINE_CONTROL;
    if (bstr_cmp_c(method, "MERGE") == 0) return HTP_M_MERGE;
    if (bstr_cmp_c(method, "INVALID") == 0) return HTP_M_INVALID;
    if (bstr_cmp_c(method, "HEAD") == 0) return HTP_M_HEAD;

    return HTP_M_UNKNOWN;
}

/**
 * Is the given line empty? This function expects the line to have
 * a terminating LF.
 *
 * @param[in] data
 * @param[in] len
 * @return 0 or 1
 */
int htp_is_line_empty(unsigned char *data, size_t len) {
    if ((len == 1) || ((len == 2) && (data[0] == CR))) {
        return 1;
    }

    return 0;
}

/**
 * Does line consist entirely of whitespace characters?
 * 
 * @param[in] data
 * @param[in] len
 * @return 0 or 1
 */
int htp_is_line_whitespace(unsigned char *data, size_t len) {
    size_t i;

    for (i = 0; i < len; i++) {
        if (!isspace(data[i])) {
            return 0;
        }
    }

    return 1;
}

/**
 * Parses Content-Length string (positive decimal number).
 * White space is allowed before and after the number.
 *
 * @param[in] b
 * @return Content-Length as a number, or -1 on error.
 */
int64_t htp_parse_content_length(bstr *b) {
    return htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(b), bstr_len(b), 10);
}

/**
 * Parses chunk length (positive hexadecimal number). White space is allowed before
 * and after the number. An error will be returned if the chunk length is greater than
 * INT32_MAX.
 *
 * @param[in] data
 * @param[in] len
 * @return Chunk length, or a negative number on error.
 */
int64_t htp_parse_chunked_length(unsigned char *data, size_t len) {
    // skip leading line feeds and other control chars
    while (len) {
        unsigned char c = *data;
        if (!(c == 0x0d || c == 0x0a || c == 0x20 || c == 0x09 || c == 0x0b || c == 0x0c))
            break;
        data++;
        len--;
    }
    if (len == 0)
        return -1004;

    // find how much of the data is correctly formatted
    size_t i = 0;
    while (i < len) {
        unsigned char c = data[i];
        if (!(isdigit(c) ||
            (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')))
            break;
        i++;
    }
    // cut off trailing junk
    if (i != len) {
        len = i;
    }

    int64_t chunk_len = htp_parse_positive_integer_whitespace(data, len, 16);
    if (chunk_len < 0) return chunk_len;
    if (chunk_len > INT32_MAX) return -1;
    return chunk_len;
}

/**
 * A somewhat forgiving parser for a positive integer in a given base.
 * Only LWS is allowed before and after the number.
 * 
 * @param[in] data
 * @param[in] len
 * @param[in] base
 * @return The parsed number on success; a negative number on error.
 */
int64_t htp_parse_positive_integer_whitespace(unsigned char *data, size_t len, int base) {
    if (len == 0) return -1003;

    size_t last_pos;
    size_t pos = 0;

    // Ignore LWS before
    while ((pos < len) && (htp_is_lws(data[pos]))) pos++;
    if (pos == len) return -1001;

    int64_t r = bstr_util_mem_to_pint(data + pos, len - pos, base, &last_pos);
    if (r < 0) return r;

    // Move after the last digit
    pos += last_pos;

    // Ignore LWS after
    while (pos < len) {
        if (!htp_is_lws(data[pos])) {
            return -1002;
        }

        pos++;
    }

    return r;
}

#ifdef HTP_DEBUG

/**
 * Prints one log message to stderr.
 *
 * @param[in] stream
 * @param[in] log
 */
void htp_print_log(FILE *stream, htp_log_t *log) {
    if (log->code != 0) {
        fprintf(stream, "[%d][code %d][file %s][line %d] %s\n", log->level,
                log->code, log->file, log->line, log->msg);
    } else {
        fprintf(stream, "[%d][file %s][line %d] %s\n", log->level,
                log->file, log->line, log->msg);
    }
}
#endif

/**
 * Records one log message.
 * 
 * @param[in] connp
 * @param[in] file
 * @param[in] line
 * @param[in] level
 * @param[in] code
 * @param[in] fmt
 */
void htp_log(htp_connp_t *connp, const char *file, int line, enum htp_log_level_t level, int code, const char *fmt, ...) {
    if (connp == NULL) return;

    char buf[1024];
    va_list args;

    // Ignore messages below our log level.
    if (connp->cfg->log_level < level) {
        return;
    }

    va_start(args, fmt);

    int r = vsnprintf(buf, 1024, fmt, args);

    va_end(args);

    if (r < 0) {
        snprintf(buf, 1024, "[vnsprintf returned error %d]", r);
    } else if (r >= 1024) {
        // Indicate overflow with a '+' at the end.
        buf[1022] = '+';
        buf[1023] = '\0';
    }

    // Create a new log entry.

    htp_log_t *log = calloc(1, sizeof (htp_log_t));
    if (log == NULL) return;

    log->connp = connp;
    log->file = file;
    log->line = line;
    log->level = level;
    log->code = code;
    log->msg = strdup(buf);

    htp_list_add(connp->conn->messages, log);

    if (level == HTP_LOG_ERROR) {
        connp->last_error = log;
    }

    #ifdef HTP_DEBUG
    fprintf(stderr, "[LOG] %s\n", log->msg);
    #endif

    /* coverity[check_return] */
    htp_hook_run_all(connp->cfg->hook_log, log);
}

/**
 * Determines if the given line is a continuation (of some previous line).
 * 
 * @param[in] data
 * @param[in] len
 * @return 0 or 1 for false and true, respectively. Returns -1 on error (NULL pointer or length zero).
 */
int htp_connp_is_line_folded(unsigned char *data, size_t len) {
    if ((data == NULL) || (len == 0)) return -1;
    return htp_is_folding_char(data[0]);
}

int htp_is_folding_char(int c) {
    if (htp_is_lws(c)) return 1;
    else return 0;
}

/**
 * Determines if the given line is a request terminator.
 *
 * @param[in] connp
 * @param[in] data
 * @param[in] len
 * @return 0 or 1
 */
int htp_connp_is_line_terminator(htp_connp_t *connp, unsigned char *data, size_t len) {
    // Is this the end of request headers?
    switch (connp->cfg->server_personality) {
        case HTP_SERVER_IIS_5_1:
            // IIS 5 will accept a whitespace line as a terminator
            if (htp_is_line_whitespace(data, len)) {
                return 1;
            }

            // Fall through
        default:
            // Treat an empty line as terminator
            if (htp_is_line_empty(data, len)) {
                return 1;
            }
            break;
    }

    return 0;
}

/**
 * Determines if the given line can be ignored when it appears before a request.
 *
 * @param[in] connp
 * @param[in] data
 * @param[in] len
 * @return 0 or 1
 */
int htp_connp_is_line_ignorable(htp_connp_t *connp, unsigned char *data, size_t len) {
    return htp_connp_is_line_terminator(connp, data, len);
}

static htp_status_t htp_parse_port(unsigned char *data, size_t len, int *port, int *invalid) {
    if (len == 0) {
        *port = -1;
        *invalid = 1;
        return HTP_OK;
    }

    int64_t port_parsed = htp_parse_positive_integer_whitespace(data, len, 10);

    if (port_parsed < 0) {
        // Failed to parse the port number.
        *port = -1;
        *invalid = 1;
    } else if ((port_parsed > 0) && (port_parsed < 65536)) {
        // Valid port number.
        *port = port_parsed;
    } else {
        // Port number out of range.
        *port = -1;
        *invalid = 1;
    }

    return HTP_OK;
}

/**
 * Parses an authority string, which consists of a hostname with an optional port number; username
 * and password are not allowed and will not be handled.
 *
 * @param[in] hostport
 * @param[out] hostname A bstring containing the hostname, or NULL if the hostname is invalid. If this value
 *                      is not NULL, the caller assumes responsibility for memory management.
 * @param[out] port Port as text, or NULL if not provided.
 * @param[out] port_number Port number, or -1 if the port is not present or invalid.
 * @param[out] invalid Set to 1 if any part of the authority is invalid.
 * @return HTP_OK on success, HTP_ERROR on memory allocation failure.
 */
htp_status_t htp_parse_hostport(bstr *hostport, bstr **hostname, bstr **port, int *port_number, int *invalid) {
    if ((hostport == NULL) || (hostname == NULL) || (port_number == NULL) || (invalid == NULL)) return HTP_ERROR;

    *hostname = NULL;
    if (port != NULL) {
        *port = NULL;
    }
    *port_number = -1;
    *invalid = 0;

    unsigned char *data = bstr_ptr(hostport);
    size_t len = bstr_len(hostport);

    bstr_util_mem_trim(&data, &len);

    if (len == 0) {
        *invalid = 1;
        return HTP_OK;
    }

    // Check for an IPv6 address.
    if (data[0] == '[') {
        // IPv6 host.

        // Find the end of the IPv6 address.
        size_t pos = 0;
        while ((pos < len) && (data[pos] != ']')) pos++;
        if (pos == len) {
            *invalid = 1;
            return HTP_OK;
        }

        *hostname = bstr_dup_mem(data, pos + 1);
        if (*hostname == NULL) return HTP_ERROR;

        // Over the ']'.
        pos++;
        if (pos == len) return HTP_OK;

        // Handle port.
        if (data[pos] == ':') {
            if (port != NULL) {
                *port = bstr_dup_mem(data + pos + 1, len - pos - 1);
                if (*port == NULL) {
                    bstr_free(*hostname);
                    return HTP_ERROR;
                }
            }

            return htp_parse_port(data + pos + 1, len - pos - 1, port_number, invalid);
        } else {
            *invalid = 1;
            return HTP_OK;
        }
    } else {
        // Not IPv6 host.

        // Is there a colon?
        unsigned char *colon = memchr(data, ':', len);
        if (colon == NULL) {
            // Hostname alone, no port.

            *hostname = bstr_dup_mem(data, len);
            if (*hostname == NULL) return HTP_ERROR;

            bstr_to_lowercase(*hostname);
        } else {
            // Hostname and port.

            // Ignore whitespace at the end of hostname.
            unsigned char *hostend = colon;
            while ((hostend > data) && (isspace(*(hostend - 1)))) hostend--;

            *hostname = bstr_dup_mem(data, hostend - data);
            if (*hostname == NULL) return HTP_ERROR;

            if (port != NULL) {
                *port = bstr_dup_mem(colon + 1, len - (colon + 1 - data));
                if (*port == NULL) {
                    bstr_free(*hostname);
                    return HTP_ERROR;
                }
            }

            return htp_parse_port(colon + 1, len - (colon + 1 - data), port_number, invalid);
        }
    }

    return HTP_OK;
}

/**
 * Parses hostport provided in the URI.
 *
 * @param[in] connp
 * @param[in] hostport
 * @param[in] uri
 * @return HTP_OK on success or HTP_ERROR error.
 */
int htp_parse_uri_hostport(htp_connp_t *connp, bstr *hostport, htp_uri_t *uri) {
    int invalid;

    htp_status_t rc = htp_parse_hostport(hostport, &(uri->hostname), &(uri->port), &(uri->port_number), &invalid);
    if (rc != HTP_OK) return rc;

    if (invalid) {
        connp->in_tx->flags |= HTP_HOSTU_INVALID;
    }

    if (uri->hostname != NULL) {
        if (htp_validate_hostname(uri->hostname) == 0) {
            connp->in_tx->flags |= HTP_HOSTU_INVALID;
        }
    }

    return HTP_OK;
}

/**
 * Parses hostport provided in the Host header.
 * 
 * @param[in] hostport
 * @param[out] hostname
 * @param[out] port
 * @param[out] port_number
 * @param[out] flags
 * @return HTP_OK on success or HTP_ERROR error.
 */
htp_status_t htp_parse_header_hostport(bstr *hostport, bstr **hostname, bstr **port, int *port_number, uint64_t *flags) {
    int invalid;

    htp_status_t rc = htp_parse_hostport(hostport, hostname, port, port_number, &invalid);
    if (rc != HTP_OK) return rc;

    if (invalid) {
        *flags |= HTP_HOSTH_INVALID;
    }

    if (*hostname != NULL) {
        if (htp_validate_hostname(*hostname) == 0) {
            *flags |= HTP_HOSTH_INVALID;
        }
    }

    return HTP_OK;
}

/**
 * Parses request URI, making no attempt to validate the contents.
 * 
 * @param[in] input
 * @param[in] uri
 * @return HTP_ERROR on memory allocation failure, HTP_OK otherwise
 */
int htp_parse_uri(bstr *input, htp_uri_t **uri) {
    // Allow a htp_uri_t structure to be provided on input,
    // but allocate a new one if the structure is NULL.
    if (*uri == NULL) {
        *uri = calloc(1, sizeof (htp_uri_t));
        if (*uri == NULL) return HTP_ERROR;
    }

    if (input == NULL) {
        // The input might be NULL on requests that don't actually
        // contain the URI. We allow that.
        return HTP_OK;
    }

    unsigned char *data = bstr_ptr(input);
    size_t len = bstr_len(input);
    size_t start, pos;

    if (len == 0) {
        // Empty string.
        return HTP_OK;
    }

    pos = 0;

    // Scheme test: if it doesn't start with a forward slash character (which it must
    // for the contents to be a path or an authority, then it must be the scheme part
    if (data[0] != '/') {
        // Parse scheme        

        // Find the colon, which marks the end of the scheme part
        start = pos;
        while ((pos < len) && (data[pos] != ':')) pos++;

        if (pos >= len) {
            // We haven't found a colon, which means that the URI
            // is invalid. Apache will ignore this problem and assume
            // the URI contains an invalid path so, for the time being,
            // we are going to do the same.
            pos = 0;
        } else {
            // Make a copy of the scheme
            (*uri)->scheme = bstr_dup_mem(data + start, pos - start);
            if ((*uri)->scheme == NULL) return HTP_ERROR;

            // Go over the colon
            pos++;
        }
    }

    // Authority test: two forward slash characters and it's an authority.
    // One, three or more slash characters, and it's a path. We, however,
    // only attempt to parse authority if we've seen a scheme.
    if ((*uri)->scheme != NULL)
        if ((pos + 2 < len) && (data[pos] == '/') && (data[pos + 1] == '/') && (data[pos + 2] != '/')) {
            // Parse authority

            // Go over the two slash characters
            start = pos = pos + 2;

            // Authority ends with a question mark, forward slash or hash
            while ((pos < len) && (data[pos] != '?') && (data[pos] != '/') && (data[pos] != '#')) pos++;

            unsigned char *hostname_start;
            size_t hostname_len;

            // Are the credentials included in the authority?
            unsigned char *m = memchr(data + start, '@', pos - start);
            if (m != NULL) {
                // Credentials present
                unsigned char *credentials_start = data + start;
                size_t credentials_len = m - data - start;

                // Figure out just the hostname part
                hostname_start = data + start + credentials_len + 1;
                hostname_len = pos - start - credentials_len - 1;

                // Extract the username and the password
                m = memchr(credentials_start, ':', credentials_len);
                if (m != NULL) {
                    // Username and password
                    (*uri)->username = bstr_dup_mem(credentials_start, m - credentials_start);
                    if ((*uri)->username == NULL) return HTP_ERROR;
                    (*uri)->password = bstr_dup_mem(m + 1, credentials_len - (m - credentials_start) - 1);
                    if ((*uri)->password == NULL) return HTP_ERROR;
                } else {
                    // Username alone
                    (*uri)->username = bstr_dup_mem(credentials_start, credentials_len);
                    if ((*uri)->username == NULL) return HTP_ERROR;
                }
            } else {
                // No credentials
                hostname_start = data + start;
                hostname_len = pos - start;
            }

            // Parsing authority without credentials.
            if ((hostname_len > 0) && (hostname_start[0] == '[')) {
                // IPv6 address.

                m = memchr(hostname_start, ']', hostname_len);
                if (m == NULL) {
                    // Invalid IPv6 address; use the entire string as hostname.
                    (*uri)->hostname = bstr_dup_mem(hostname_start, hostname_len);
                    if ((*uri)->hostname == NULL) return HTP_ERROR;
                } else {
                    (*uri)->hostname = bstr_dup_mem(hostname_start, m - hostname_start + 1);
                    if ((*uri)->hostname == NULL) return HTP_ERROR;

                    // Is there a port?
                    hostname_len = hostname_len - (m - hostname_start + 1);
                    hostname_start = m + 1;

                    // Port string
                    m = memchr(hostname_start, ':', hostname_len);
                    if (m != NULL) {
                        size_t port_len = hostname_len - (m - hostname_start) - 1;
                        (*uri)->port = bstr_dup_mem(m + 1, port_len);
                        if ((*uri)->port == NULL) return HTP_ERROR;
                    }
                }
            } else {
                // Not IPv6 address.

                m = memchr(hostname_start, ':', hostname_len);
                if (m != NULL) {
                    size_t port_len = hostname_len - (m - hostname_start) - 1;
                    hostname_len = hostname_len - port_len - 1;

                    // Port string
                    (*uri)->port = bstr_dup_mem(m + 1, port_len);
                    if ((*uri)->port == NULL) return HTP_ERROR;
                }

                // Hostname
                (*uri)->hostname = bstr_dup_mem(hostname_start, hostname_len);
                if ((*uri)->hostname == NULL) return HTP_ERROR;
            }
        }

    // Path
    start = pos;

    // The path part will end with a question mark or a hash character, which
    // mark the beginning of the query part or the fragment part, respectively.
    while ((pos < len) && (data[pos] != '?') && (data[pos] != '#')) pos++;

    // Path
    (*uri)->path = bstr_dup_mem(data + start, pos - start);
    if ((*uri)->path == NULL) return HTP_ERROR;

    if (pos == len) return HTP_OK;

    // Query
    if (data[pos] == '?') {
        // Step over the question mark
        start = pos + 1;

        // The query part will end with the end of the input
        // or the beginning of the fragment part
        while ((pos < len) && (data[pos] != '#')) pos++;

        // Query string
        (*uri)->query = bstr_dup_mem(data + start, pos - start);
        if ((*uri)->query == NULL) return HTP_ERROR;

        if (pos == len) return HTP_OK;
    }

    // Fragment
    if (data[pos] == '#') {
        // Step over the hash character
        start = pos + 1;

        // Fragment; ends with the end of the input
        (*uri)->fragment = bstr_dup_mem(data + start, len - start);
        if ((*uri)->fragment == NULL) return HTP_ERROR;
    }

    return HTP_OK;
}

/**
 * Convert two input bytes, pointed to by the pointer parameter,
 * into a single byte by assuming the input consists of hexadecimal
 * characters. This function will happily convert invalid input.
 *
 * @param[in] what
 * @return hex-decoded byte
 */
static unsigned char x2c(unsigned char *what) {
    register unsigned char digit;

    digit = (what[0] >= 'A' ? ((what[0] & 0xdf) - 'A') + 10 : (what[0] - '0'));
    digit *= 16;
    digit += (what[1] >= 'A' ? ((what[1] & 0xdf) - 'A') + 10 : (what[1] - '0'));

    return digit;
}

/**
 * Convert a Unicode codepoint into a single-byte, using best-fit
 * mapping (as specified in the provided configuration structure).
 *
 * @param[in] cfg
 * @param[in] codepoint
 * @return converted single byte
 */
static uint8_t bestfit_codepoint(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, uint32_t codepoint) {
    // Is it a single-byte codepoint?
    if (codepoint < 0x100) {
        return (uint8_t) codepoint;
    }

    // Our current implementation converts only the 2-byte codepoints.
    if (codepoint > 0xffff) {
        return cfg->decoder_cfgs[ctx].bestfit_replacement_byte;
    }

    uint8_t *p = cfg->decoder_cfgs[ctx].bestfit_map;

    // TODO Optimize lookup.

    for (;;) {
        uint32_t x = (p[0] << 8) + p[1];

        if (x == 0) {
            return cfg->decoder_cfgs[ctx].bestfit_replacement_byte;
        }

        if (x == codepoint) {
            return p[2];
        }

        // Move to the next triplet
        p += 3;
    }
}

/**
 * Decode a UTF-8 encoded path. Overlong characters will be decoded, invalid
 * characters will be left as-is. Best-fit mapping will be used to convert
 * UTF-8 into a single-byte stream.
 *
 * @param[in] cfg
 * @param[in] tx
 * @param[in] path
 */
void htp_utf8_decode_path_inplace(htp_cfg_t *cfg, htp_tx_t *tx, bstr *path) {
    if (path == NULL) return;

    uint8_t *data = bstr_ptr(path);
    if (data == NULL) return;

    size_t len = bstr_len(path);
    size_t rpos = 0;
    size_t wpos = 0;
    uint32_t codepoint = 0;
    uint32_t state = HTP_UTF8_ACCEPT;
    uint32_t counter = 0;
    uint8_t seen_valid = 0;

    while ((rpos < len)&&(wpos < len)) {
        counter++;

        switch (htp_utf8_decode_allow_overlong(&state, &codepoint, data[rpos])) {
            case HTP_UTF8_ACCEPT:
                if (counter == 1) {
                    // ASCII character, which we just copy.
                    data[wpos++] = (uint8_t) codepoint;
                } else {
                    // A valid UTF-8 character, which we need to convert.

                    seen_valid = 1;

                    // Check for overlong characters and set the flag accordingly.
                    switch (counter) {
                        case 2:
                            if (codepoint < 0x80) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 3:
                            if (codepoint < 0x800) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 4:
                            if (codepoint < 0x10000) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                    }

                    // Special flag for half-width/full-width evasion.
                    if ((codepoint >= 0xff00) && (codepoint <= 0xffef)) {
                        tx->flags |= HTP_PATH_HALF_FULL_RANGE;
                    }

                    // Use best-fit mapping to convert to a single byte.
                    data[wpos++] = bestfit_codepoint(cfg, HTP_DECODER_URL_PATH, codepoint);
                }

                // Advance over the consumed byte and reset the byte counter.
                rpos++;
                counter = 0;

                break;

            case HTP_UTF8_REJECT:
                // Invalid UTF-8 character.

                tx->flags |= HTP_PATH_UTF8_INVALID;

                // Is the server expected to respond with 400?
                if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].utf8_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                    tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].utf8_invalid_unwanted;
                }

                // Output the replacement byte, replacing one or more invalid bytes.
                data[wpos++] = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].bestfit_replacement_byte;

                // If the invalid byte was first in a sequence, consume it. Otherwise,
                // assume it's the starting byte of the next character.
                if (counter == 1) {
                    rpos++;
                }

                // Reset the decoder state and continue decoding.
                state = HTP_UTF8_ACCEPT;
                codepoint = 0;
                counter = 0;

                break;

            default:
                // Keep going; the character is not yet formed.
                rpos++;
                break;
        }
    }

    // Did the input stream seem like a valid UTF-8 string?
    if ((seen_valid) && (!(tx->flags & HTP_PATH_UTF8_INVALID))) {
        tx->flags |= HTP_PATH_UTF8_VALID;
    }

    // Adjust the length of the string, because
    // we're doing in-place decoding.
    bstr_adjust_len(path, wpos);
}

/**
 * Validate a path that is quite possibly UTF-8 encoded.
 * 
 * @param[in] tx
 * @param[in] path
 */
void htp_utf8_validate_path(htp_tx_t *tx, bstr *path) {
    unsigned char *data = bstr_ptr(path);
    size_t len = bstr_len(path);
    size_t rpos = 0;
    uint32_t codepoint = 0;
    uint32_t state = HTP_UTF8_ACCEPT;
    uint32_t counter = 0; // How many bytes used by a UTF-8 character.
    uint8_t seen_valid = 0;

    while (rpos < len) {
        counter++;

        switch (htp_utf8_decode_allow_overlong(&state, &codepoint, data[rpos])) {
            case HTP_UTF8_ACCEPT:
                // We have a valid character.

                if (counter > 1) {
                    // A valid UTF-8 character, consisting of 2 or more bytes.

                    seen_valid = 1;

                    // Check for overlong characters and set the flag accordingly.
                    switch (counter) {
                        case 2:
                            if (codepoint < 0x80) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 3:
                            if (codepoint < 0x800) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                        case 4:
                            if (codepoint < 0x10000) {
                                tx->flags |= HTP_PATH_UTF8_OVERLONG;
                            }
                            break;
                    }
                }

                // Special flag for half-width/full-width evasion.
                if ((codepoint > 0xfeff) && (codepoint < 0x010000)) {
                    tx->flags |= HTP_PATH_HALF_FULL_RANGE;
                }

                // Advance over the consumed byte and reset the byte counter.
                rpos++;
                counter = 0;

                break;

            case HTP_UTF8_REJECT:
                // Invalid UTF-8 character.

                tx->flags |= HTP_PATH_UTF8_INVALID;

                // Override the decoder state because we want to continue decoding.
                state = HTP_UTF8_ACCEPT;

                // Advance over the consumed byte and reset the byte counter.
                rpos++;
                counter = 0;

                break;

            default:
                // Keep going; the character is not yet formed.
                rpos++;
                break;
        }
    }

    // Did the input stream seem like a valid UTF-8 string?
    if ((seen_valid) && (!(tx->flags & HTP_PATH_UTF8_INVALID))) {
        tx->flags |= HTP_PATH_UTF8_VALID;
    }
}

/**
 * Decode a %u-encoded character, using best-fit mapping as necessary. Path version.
 *
 * @param[in] cfg
 * @param[in] tx
 * @param[in] data
 * @return decoded byte
 */
static int decode_u_encoding_path(htp_cfg_t *cfg, htp_tx_t *tx, unsigned char *data) {
    unsigned int c1 = x2c(data);
    unsigned int c2 = x2c(data + 2);
    int r = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].bestfit_replacement_byte;

    if (c1 == 0x00) {
        r = c2;
        tx->flags |= HTP_PATH_OVERLONG_U;
    } else {
        // Check for fullwidth form evasion
        if (c1 == 0xff) {
            tx->flags |= HTP_PATH_HALF_FULL_RANGE;
        }

        if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].u_encoding_unwanted != HTP_UNWANTED_IGNORE) {
            tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].u_encoding_unwanted;
        }

        // Use best-fit mapping
        unsigned char *p = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].bestfit_map;

        // TODO Optimize lookup.

        for (;;) {
            // Have we reached the end of the map?
            if ((p[0] == 0) && (p[1] == 0)) {
                break;
            }

            // Have we found the mapping we're looking for?
            if ((p[0] == c1) && (p[1] == c2)) {
                r = p[2];
                break;
            }

            // Move to the next triplet
            p += 3;
        }
    }

    // Check for encoded path separators
    if ((r == '/') || ((cfg->decoder_cfgs[HTP_DECODER_URL_PATH].backslash_convert_slashes) && (r == '\\'))) {
        tx->flags |= HTP_PATH_ENCODED_SEPARATOR;
    }

    return r;
}

/**
 * Decode a %u-encoded character, using best-fit mapping as necessary. Params version.
 *
 * @param[in] cfg
 * @param[in] tx
 * @param[in] data
 * @return decoded byte
 */
static int decode_u_encoding_params(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, unsigned char *data, uint64_t *flags) {
    unsigned int c1 = x2c(data);
    unsigned int c2 = x2c(data + 2);

    // Check for overlong usage first.
    if (c1 == 0) {
        (*flags) |= HTP_URLEN_OVERLONG_U;
        return c2;
    }

    // Both bytes were used.

    // Detect half-width and full-width range.
    if ((c1 == 0xff) && (c2 <= 0xef)) {
        (*flags) |= HTP_URLEN_HALF_FULL_RANGE;
    }

    // Use best-fit mapping.
    unsigned char *p = cfg->decoder_cfgs[ctx].bestfit_map;
    int r = cfg->decoder_cfgs[ctx].bestfit_replacement_byte;

    // TODO Optimize lookup.

    for (;;) {
        // Have we reached the end of the map?
        if ((p[0] == 0) && (p[1] == 0)) {
            break;
        }

        // Have we found the mapping we're looking for?
        if ((p[0] == c1) && (p[1] == c2)) {
            r = p[2];
            break;
        }

        // Move to the next triplet
        p += 3;
    }

    return r;
}

/**
 * Decode a request path according to the settings in the
 * provided configuration structure.
 *
 * @param[in] cfg
 * @param[in] tx
 * @param[in] path
 */
htp_status_t htp_decode_path_inplace(htp_tx_t *tx, bstr *path) {
    if (path == NULL) return HTP_ERROR;
    unsigned char *data = bstr_ptr(path);
    if (data == NULL) return HTP_ERROR;

    size_t len = bstr_len(path);

    htp_cfg_t *cfg = tx->cfg;

    size_t rpos = 0;
    size_t wpos = 0;
    int previous_was_separator = 0;

    while ((rpos < len) && (wpos < len)) {
        int c = data[rpos];

        // Decode encoded characters
        if (c == '%') {
            if (rpos + 2 < len) {
                int handled = 0;

                if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].u_encoding_decode) {
                    // Check for the %u encoding
                    if ((data[rpos + 1] == 'u') || (data[rpos + 1] == 'U')) {
                        handled = 1;

                        if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].u_encoding_unwanted != HTP_UNWANTED_IGNORE) {
                            tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].u_encoding_unwanted;
                        }

                        if (rpos + 5 < len) {
                            if (isxdigit(data[rpos + 2]) && (isxdigit(data[rpos + 3]))
                                    && isxdigit(data[rpos + 4]) && (isxdigit(data[rpos + 5]))) {
                                // Decode a valid %u encoding
                                c = decode_u_encoding_path(cfg, tx, &data[rpos + 2]);
                                rpos += 6;

                                if (c == 0) {
                                    tx->flags |= HTP_PATH_ENCODED_NUL;

                                    if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_encoded_unwanted != HTP_UNWANTED_IGNORE) {
                                        tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_encoded_unwanted;
                                    }
                                }
                            } else {
                                // Invalid %u encoding
                                tx->flags |= HTP_PATH_INVALID_ENCODING;

                                if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                                    tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted;
                                }

                                switch (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_handling) {
                                    case HTP_URL_DECODE_REMOVE_PERCENT:
                                        // Do not place anything in output; eat
                                        // the percent character
                                        rpos++;
                                        continue;
                                        break;
                                    case HTP_URL_DECODE_PRESERVE_PERCENT:
                                        // Leave the percent character in output
                                        rpos++;
                                        break;
                                    case HTP_URL_DECODE_PROCESS_INVALID:
                                        // Decode invalid %u encoding
                                        c = decode_u_encoding_path(cfg, tx, &data[rpos + 2]);
                                        rpos += 6;
                                        break;
                                }
                            }
                        } else {
                            // Invalid %u encoding (not enough data)
                            tx->flags |= HTP_PATH_INVALID_ENCODING;

                            if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                                tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted;
                            }

                            switch (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_handling) {
                                case HTP_URL_DECODE_REMOVE_PERCENT:
                                    // Do not place anything in output; eat
                                    // the percent character
                                    rpos++;
                                    continue;
                                    break;
                                case HTP_URL_DECODE_PRESERVE_PERCENT:
                                    // Leave the percent character in output
                                    rpos++;
                                    break;
                                case HTP_URL_DECODE_PROCESS_INVALID:
                                    // Cannot decode, because there's not enough data.
                                    // Leave the percent character in output
                                    rpos++;
                                    // TODO Configurable handling.
                                    break;
                            }
                        }
                    }
                }

                // Handle standard URL encoding
                if (!handled) {
                    if ((isxdigit(data[rpos + 1])) && (isxdigit(data[rpos + 2]))) {
                        c = x2c(&data[rpos + 1]);

                        if (c == 0) {
                            tx->flags |= HTP_PATH_ENCODED_NUL;

                            if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_encoded_unwanted != HTP_UNWANTED_IGNORE) {
                                tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_encoded_unwanted;
                            }

                            if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_encoded_terminates) {
                                bstr_adjust_len(path, wpos);
                                return HTP_OK;
                            }
                        }

                        if ((c == '/') || ((cfg->decoder_cfgs[HTP_DECODER_URL_PATH].backslash_convert_slashes) && (c == '\\'))) {
                            tx->flags |= HTP_PATH_ENCODED_SEPARATOR;

                            if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].path_separators_encoded_unwanted != HTP_UNWANTED_IGNORE) {
                                tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].path_separators_encoded_unwanted;
                            }

                            if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].path_separators_decode) {
                                // Decode
                                rpos += 3;
                            } else {
                                // Leave encoded
                                c = '%';
                                rpos++;
                            }
                        } else {
                            // Decode
                            rpos += 3;
                        }
                    } else {
                        // Invalid encoding
                        tx->flags |= HTP_PATH_INVALID_ENCODING;

                        if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                            tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted;
                        }

                        switch (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_handling) {
                            case HTP_URL_DECODE_REMOVE_PERCENT:
                                // Do not place anything in output; eat
                                // the percent character
                                rpos++;
                                continue;
                                break;
                            case HTP_URL_DECODE_PRESERVE_PERCENT:
                                // Leave the percent character in output
                                rpos++;
                                break;
                            case HTP_URL_DECODE_PROCESS_INVALID:
                                // Decode
                                c = x2c(&data[rpos + 1]);
                                rpos += 3;
                                // Note: What if an invalid encoding decodes into a path
                                //       separator? This is theoretical at the moment, because
                                //       the only platform we know doesn't convert separators is
                                //       Apache, who will also respond with 400 if invalid encoding
                                //       is encountered. Thus no check for a separator here.
                                break;
                            default:
                                // Unknown setting
                                return HTP_ERROR;
                                break;
                        }
                    }
                }
            } else {
                // Invalid URL encoding (not enough data)
                tx->flags |= HTP_PATH_INVALID_ENCODING;

                if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                    tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_unwanted;
                }

                switch (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].url_encoding_invalid_handling) {
                    case HTP_URL_DECODE_REMOVE_PERCENT:
                        // Do not place anything in output; eat
                        // the percent character
                        rpos++;
                        continue;
                        break;
                    case HTP_URL_DECODE_PRESERVE_PERCENT:
                        // Leave the percent character in output
                        rpos++;
                        break;
                    case HTP_URL_DECODE_PROCESS_INVALID:
                        // Cannot decode, because there's not enough data.
                        // Leave the percent character in output.
                        // TODO Configurable handling.
                        rpos++;
                        break;
                }
            }
        } else {
            // One non-encoded character

            // Is it a NUL byte?
            if (c == 0) {
                if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_raw_unwanted != HTP_UNWANTED_IGNORE) {
                    tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_raw_unwanted;
                }

                if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].nul_raw_terminates) {
                    // Terminate path with a raw NUL byte
                    bstr_adjust_len(path, wpos);
                    return HTP_OK;
                    break;
                }
            }

            rpos++;
        }

        // Place the character into output

        // Check for control characters
        if (c < 0x20) {
            if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].control_chars_unwanted != HTP_UNWANTED_IGNORE) {
                tx->response_status_expected_number = cfg->decoder_cfgs[HTP_DECODER_URL_PATH].control_chars_unwanted;
            }
        }

        // Convert backslashes to forward slashes, if necessary
        if ((c == '\\') && (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].backslash_convert_slashes)) {
            c = '/';
        }

        // Lowercase characters, if necessary
        if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].convert_lowercase) {
            c = tolower(c);
        }

        // If we're compressing separators then we need
        // to track if the previous character was a separator
        if (cfg->decoder_cfgs[HTP_DECODER_URL_PATH].path_separators_compress) {
            if (c == '/') {
                if (!previous_was_separator) {
                    data[wpos++] = c;
                    previous_was_separator = 1;
                } else {
                    // Do nothing; we don't want
                    // another separator in output
                }
            } else {
                data[wpos++] = c;
                previous_was_separator = 0;
            }
        } else {
            data[wpos++] = c;
        }
    }

    bstr_adjust_len(path, wpos);

    return HTP_OK;
}

htp_status_t htp_tx_urldecode_uri_inplace(htp_tx_t *tx, bstr *input) {
    uint64_t flags = 0;

    htp_status_t rc = htp_urldecode_inplace_ex(tx->cfg, HTP_DECODER_URL_PATH, input, &flags, &(tx->response_status_expected_number));

    if (flags & HTP_URLEN_INVALID_ENCODING) {
        tx->flags |= HTP_PATH_INVALID_ENCODING;
    }

    if (flags & HTP_URLEN_ENCODED_NUL) {
        tx->flags |= HTP_PATH_ENCODED_NUL;
    }

    if (flags & HTP_URLEN_RAW_NUL) {
        tx->flags |= HTP_PATH_RAW_NUL;
    }

    return rc;
}

htp_status_t htp_tx_urldecode_params_inplace(htp_tx_t *tx, bstr *input) {
    return htp_urldecode_inplace_ex(tx->cfg, HTP_DECODER_URLENCODED, input, &(tx->flags), &(tx->response_status_expected_number));
}

htp_status_t htp_urldecode_inplace(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, bstr *input, uint64_t *flags) {
    int expected_status_code = 0;
    return htp_urldecode_inplace_ex(cfg, ctx, input, flags, &expected_status_code);
}

htp_status_t htp_urldecode_inplace_ex(htp_cfg_t *cfg, enum htp_decoder_ctx_t ctx, bstr *input, uint64_t *flags, int *expected_status_code) {
    if (input == NULL) return HTP_ERROR;

    unsigned char *data = bstr_ptr(input);
    if (data == NULL) return HTP_ERROR;
    size_t len = bstr_len(input);

    size_t rpos = 0;
    size_t wpos = 0;

    while ((rpos < len) && (wpos < len)) {
        int c = data[rpos];

        // Decode encoded characters.
        if (c == '%') {
            // Need at least 2 additional bytes for %HH.
            if (rpos + 2 < len) {
                int handled = 0;

                // Decode %uHHHH encoding, but only if allowed in configuration.
                if (cfg->decoder_cfgs[ctx].u_encoding_decode) {
                    // The next character must be a case-insensitive u.
                    if ((data[rpos + 1] == 'u') || (data[rpos + 1] == 'U')) {
                        handled = 1;

                        if (cfg->decoder_cfgs[ctx].u_encoding_unwanted != HTP_UNWANTED_IGNORE) {
                            (*expected_status_code) = cfg->decoder_cfgs[ctx].u_encoding_unwanted;
                        }

                        // Need at least 5 additional bytes for %uHHHH.
                        if (rpos + 5 < len) {
                            if (isxdigit(data[rpos + 2]) && (isxdigit(data[rpos + 3]))
                                    && isxdigit(data[rpos + 4]) && (isxdigit(data[rpos + 5]))) {
                                // Decode a valid %u encoding.
                                c = decode_u_encoding_params(cfg, ctx, &(data[rpos + 2]), flags);
                                rpos += 6;
                            } else {
                                // Invalid %u encoding (could not find 4 xdigits).
                                (*flags) |= HTP_URLEN_INVALID_ENCODING;

                                if (cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                                    (*expected_status_code) = cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted;
                                }

                                switch (cfg->decoder_cfgs[ctx].url_encoding_invalid_handling) {
                                    case HTP_URL_DECODE_REMOVE_PERCENT:
                                        // Do not place anything in output; consume the %.
                                        rpos++;
                                        continue;
                                        break;
                                    case HTP_URL_DECODE_PRESERVE_PERCENT:
                                        // Leave the % in output.
                                        rpos++;
                                        break;
                                    case HTP_URL_DECODE_PROCESS_INVALID:
                                        // Decode invalid %u encoding.
                                        c = decode_u_encoding_params(cfg, ctx, &(data[rpos + 2]), flags);
                                        rpos += 6;
                                        break;
                                }
                            }
                        } else {
                            // Invalid %u encoding; not enough data.
                            (*flags) |= HTP_URLEN_INVALID_ENCODING;

                            if (cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                                (*expected_status_code) = cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted;
                            }

                            switch (cfg->decoder_cfgs[ctx].url_encoding_invalid_handling) {
                                case HTP_URL_DECODE_REMOVE_PERCENT:
                                    // Do not place anything in output; consume the %.
                                    rpos++;
                                    continue;
                                    break;
                                case HTP_URL_DECODE_PRESERVE_PERCENT:
                                    // Leave the % in output.
                                    rpos++;
                                    break;
                                case HTP_URL_DECODE_PROCESS_INVALID:
                                    // Cannot decode because there's not enough data.
                                    // Leave the % in output.
                                    // TODO Configurable handling of %, u, etc.
                                    rpos++;
                                    break;
                            }
                        }
                    }
                }

                // Handle standard URL encoding.
                if (!handled) {
                    // Need 2 hexadecimal digits.
                    if ((isxdigit(data[rpos + 1])) && (isxdigit(data[rpos + 2]))) {
                        // Decode %HH encoding.
                        c = x2c(&(data[rpos + 1]));
                        rpos += 3;
                    } else {
                        // Invalid encoding (enough bytes, but not hexadecimal digits).
                        (*flags) |= HTP_URLEN_INVALID_ENCODING;

                        if (cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                            (*expected_status_code) = cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted;
                        }

                        switch (cfg->decoder_cfgs[ctx].url_encoding_invalid_handling) {
                            case HTP_URL_DECODE_REMOVE_PERCENT:
                                // Do not place anything in output; consume the %.
                                rpos++;
                                continue;
                                break;
                            case HTP_URL_DECODE_PRESERVE_PERCENT:
                                // Leave the % in output.
                                rpos++;
                                break;
                            case HTP_URL_DECODE_PROCESS_INVALID:
                                // Decode.
                                c = x2c(&(data[rpos + 1]));
                                rpos += 3;
                                break;
                        }
                    }
                }
            } else {
                // Invalid encoding; not enough data (at least 2 bytes required).
                (*flags) |= HTP_URLEN_INVALID_ENCODING;

                if (cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted != HTP_UNWANTED_IGNORE) {
                    (*expected_status_code) = cfg->decoder_cfgs[ctx].url_encoding_invalid_unwanted;
                }

                switch (cfg->decoder_cfgs[ctx].url_encoding_invalid_handling) {
                    case HTP_URL_DECODE_REMOVE_PERCENT:
                        // Do not place anything in output; consume the %.
                        rpos++;
                        continue;
                        break;
                    case HTP_URL_DECODE_PRESERVE_PERCENT:
                        // Leave the % in output.
                        rpos++;
                        break;
                    case HTP_URL_DECODE_PROCESS_INVALID:
                        // Cannot decode because there's not enough data.
                        // Leave the % in output.
                        // TODO Configurable handling of %, etc.
                        rpos++;
                        break;
                }
            }

            // Did we get an encoded NUL byte?
            if (c == 0) {
                if (cfg->decoder_cfgs[ctx].nul_encoded_unwanted != HTP_UNWANTED_IGNORE) {
                    (*expected_status_code) = cfg->decoder_cfgs[ctx].nul_encoded_unwanted;
                }

                (*flags) |= HTP_URLEN_ENCODED_NUL;

                if (cfg->decoder_cfgs[ctx].nul_encoded_terminates) {
                    // Terminate the path at the raw NUL byte.
                    bstr_adjust_len(input, wpos);
                    return 1;
                }
            }

            data[wpos++] = c;
        } else if (c == '+') {
            // Decoding of the plus character is conditional on the configuration.

            if (cfg->decoder_cfgs[ctx].plusspace_decode) {
                c = 0x20;
            }

            rpos++;
            data[wpos++] = c;
        } else {
            // One non-encoded byte.

            // Did we get a raw NUL byte?
            if (c == 0) {
                if (cfg->decoder_cfgs[ctx].nul_raw_unwanted != HTP_UNWANTED_IGNORE) {
                    (*expected_status_code) = cfg->decoder_cfgs[ctx].nul_raw_unwanted;
                }

                (*flags) |= HTP_URLEN_RAW_NUL;

                if (cfg->decoder_cfgs[ctx].nul_raw_terminates) {
                    // Terminate the path at the encoded NUL byte.
                    bstr_adjust_len(input, wpos);
                    return HTP_OK;
                }
            }

            rpos++;
            data[wpos++] = c;
        }
    }

    bstr_adjust_len(input, wpos);

    return HTP_OK;
}

/**
 * Normalize a previously-parsed request URI.
 *
 * @param[in] connp
 * @param[in] incomplete
 * @param[in] normalized
 * @return HTP_OK or HTP_ERROR
 */
int htp_normalize_parsed_uri(htp_tx_t *tx, htp_uri_t *incomplete, htp_uri_t *normalized) {
    // Scheme.
    if (incomplete->scheme != NULL) {
        // Duplicate and convert to lowercase.
        normalized->scheme = bstr_dup_lower(incomplete->scheme);
        if (normalized->scheme == NULL) return HTP_ERROR;
    }

    // Username.
    if (incomplete->username != NULL) {
        normalized->username = bstr_dup(incomplete->username);
        if (normalized->username == NULL) return HTP_ERROR;
        htp_tx_urldecode_uri_inplace(tx, normalized->username);
    }

    // Password.
    if (incomplete->password != NULL) {
        normalized->password = bstr_dup(incomplete->password);
        if (normalized->password == NULL) return HTP_ERROR;
        htp_tx_urldecode_uri_inplace(tx, normalized->password);
    }

    // Hostname.
    if (incomplete->hostname != NULL) {
        // We know that incomplete->hostname does not contain
        // port information, so no need to check for it here.
        normalized->hostname = bstr_dup(incomplete->hostname);
        if (normalized->hostname == NULL) return HTP_ERROR;
        htp_tx_urldecode_uri_inplace(tx, normalized->hostname);
        htp_normalize_hostname_inplace(normalized->hostname);
    }

    // Port.
    if (incomplete->port != NULL) {
        int64_t port_parsed = htp_parse_positive_integer_whitespace(
                bstr_ptr(incomplete->port), bstr_len(incomplete->port), 10);

        if (port_parsed < 0) {
            // Failed to parse the port number.
            normalized->port_number = -1;
            tx->flags |= HTP_HOSTU_INVALID;
        } else if ((port_parsed > 0) && (port_parsed < 65536)) {
            // Valid port number.
            normalized->port_number = (int) port_parsed;
        } else {
            // Port number out of range.
            normalized->port_number = -1;
            tx->flags |= HTP_HOSTU_INVALID;
        }
    } else {
        normalized->port_number = -1;
    }

    // Path.
    if (incomplete->path != NULL) {
        // Make a copy of the path, so that we can work on it.
        normalized->path = bstr_dup(incomplete->path);
        if (normalized->path == NULL) return HTP_ERROR;

        // Decode URL-encoded (and %u-encoded) characters, as well as lowercase,
        // compress separators and convert backslashes.
        htp_decode_path_inplace(tx, normalized->path);

        // Handle UTF-8 in the path.
        if (tx->cfg->decoder_cfgs[HTP_DECODER_URL_PATH].utf8_convert_bestfit) {
            // Decode Unicode characters into a single-byte stream, using best-fit mapping.
            htp_utf8_decode_path_inplace(tx->cfg, tx, normalized->path);
        } else {
            // No decoding, but try to validate the path as a UTF-8 stream.
            htp_utf8_validate_path(tx, normalized->path);
        }

        // RFC normalization.
        htp_normalize_uri_path_inplace(normalized->path);
    }

    // Query string.
    if (incomplete->query != NULL) {
        normalized->query = bstr_dup(incomplete->query);
        if (normalized->query == NULL) return HTP_ERROR;
    }

    // Fragment.
    if (incomplete->fragment != NULL) {
        normalized->fragment = bstr_dup(incomplete->fragment);
        if (normalized->fragment == NULL) return HTP_ERROR;
        htp_tx_urldecode_uri_inplace(tx, normalized->fragment);
    }

    return HTP_OK;
}

/**
 * Normalize request hostname. Convert all characters to lowercase and
 * remove trailing dots from the end, if present.
 *
 * @param[in] hostname
 * @return Normalized hostname.
 */
bstr *htp_normalize_hostname_inplace(bstr *hostname) {
    if (hostname == NULL) return NULL;

    bstr_to_lowercase(hostname);

    // Remove dots from the end of the string.    
    while (bstr_char_at_end(hostname, 0) == '.') bstr_chop(hostname);

    return hostname;
}

#if 0

/**
 * Replace the URI in the structure with the one provided as the parameter
 * to this function (which will typically be supplied in a Host header).
 *
 * @param[in] connp
 * @param[in] parsed_uri
 * @param[in] hostname
 */
void htp_replace_hostname(htp_connp_t *connp, htp_uri_t *parsed_uri, bstr *hostname) {
    if (hostname == NULL) return;

    bstr *new_hostname = NULL;

    int colon = bstr_chr(hostname, ':');
    if (colon == -1) {
        // Hostname alone (no port information)
        new_hostname = bstr_dup(hostname);
        if (new_hostname == NULL) return;
        htp_normalize_hostname_inplace(new_hostname);

        if (parsed_uri->hostname != NULL) bstr_free(parsed_uri->hostname);
        parsed_uri->hostname = new_hostname;
    } else {
        // Hostname and port
        new_hostname = bstr_dup_ex(hostname, 0, colon);
        if (new_hostname == NULL) return;
        // TODO Handle whitespace around hostname
        htp_normalize_hostname_inplace(new_hostname);

        if (parsed_uri->hostname != NULL) bstr_free(parsed_uri->hostname);
        parsed_uri->hostname = new_hostname;
        parsed_uri->port_number = 0;

        // Port
        int port = htp_parse_positive_integer_whitespace((unsigned char *) bstr_ptr(hostname) + colon + 1,
                bstr_len(hostname) - colon - 1, 10);
        if (port < 0) {
            // Failed to parse port
            htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Invalid server port information in request");
        } else if ((port > 0) && (port < 65536)) {
            // Valid port
            if ((connp->conn->server_port != 0) && (port != connp->conn->server_port)) {
                // Port was specified in connection and is different from the TCP port
                htp_log(connp, HTP_LOG_MARK, HTP_LOG_ERROR, 0, "Request server port=%d number differs from the actual TCP port=%d", port, connp->conn->server_port);
            } else {
                parsed_uri->port_number = port;
            }
        }
    }
}

/**
 * Is URI character reserved?
 *
 * @param[in] c
 * @return 1 if it is, 0 if it isn't
 */
int htp_is_uri_unreserved(unsigned char c) {
    if (((c >= 0x41) && (c <= 0x5a)) ||
            ((c >= 0x61) && (c <= 0x7a)) ||
            ((c >= 0x30) && (c <= 0x39)) ||
            (c == 0x2d) || (c == 0x2e) ||
            (c == 0x5f) || (c == 0x7e)) {
        return 1;
    } else {
        return 0;
    }
}

/**
 * Decode a URL-encoded string, leaving the reserved
 * characters and invalid encodings alone.
 *
 * @param[in] s
 */
void htp_uriencoding_normalize_inplace(bstr *s) {
    if (s == NULL) return;

    unsigned char *data = bstr_ptr(s);
    if (data == NULL) return;
    size_t len = bstr_len(s);

    size_t rpos = 0;
    size_t wpos = 0;

    while (rpos < len) {
        if (data[rpos] == '%') {
            if (rpos + 2 < len) {
                if (isxdigit(data[rpos + 1]) && (isxdigit(data[rpos + 2]))) {
                    unsigned char c = x2c(&data[rpos + 1]);

                    if (htp_is_uri_unreserved(c)) {
                        // Leave reserved characters encoded, but convert
                        // the hexadecimal digits to uppercase
                        data[wpos++] = data[rpos++];
                        data[wpos++] = toupper(data[rpos++]);
                        data[wpos++] = toupper(data[rpos++]);
                    } else {
                        // Decode unreserved character
                        data[wpos++] = c;
                        rpos += 3;
                    }
                } else {
                    // Invalid URL encoding: invalid hex digits

                    // Copy over what's there
                    data[wpos++] = data[rpos++];
                    data[wpos++] = toupper(data[rpos++]);
                    data[wpos++] = toupper(data[rpos++]);
                }
            } else {
                // Invalid URL encoding: string too short

                // Copy over what's there
                data[wpos++] = data[rpos++];
                while (rpos < len) {
                    data[wpos++] = toupper(data[rpos++]);
                }
            }
        } else {
            data[wpos++] = data[rpos++];
        }
    }

    bstr_adjust_len(s, wpos);
}
#endif

/**
 * Normalize URL path. This function implements the remove dot segments algorithm
 * specified in RFC 3986, section 5.2.4.
 *
 * @param[in] s
 */
void htp_normalize_uri_path_inplace(bstr *s) {
    if (s == NULL) return;

    unsigned char *data = bstr_ptr(s);
    if (data == NULL) return;
    size_t len = bstr_len(s);

    size_t rpos = 0;
    size_t wpos = 0;

    int c = -1;
    while ((rpos < len)&&(wpos < len)) {
        if (c == -1) {
            c = data[rpos++];
        }

        // A. If the input buffer begins with a prefix of "../" or "./",
        //    then remove that prefix from the input buffer; otherwise,
        if (c == '.') {
            if ((rpos + 1 < len) && (data[rpos] == '.') && (data[rpos + 1] == '/')) {
                c = -1;
                rpos += 2;
                continue;
            } else if ((rpos < len) && (data[rpos] == '/')) {
                c = -1;
                rpos += 1;
                continue;
            }
        }

        if (c == '/') {
            // B. if the input buffer begins with a prefix of "/./" or "/.",
            //    where "." is a complete path segment, then replace that
            //    prefix with "/" in the input buffer; otherwise,
            if ((rpos + 1 < len) && (data[rpos] == '.') && (data[rpos + 1] == '/')) {
                c = '/';
                rpos += 2;
                continue;
            } else if ((rpos + 1 == len) && (data[rpos] == '.')) {
                c = '/';
                rpos += 1;
                continue;
            }

            // C. if the input buffer begins with a prefix of "/../" or "/..",
            //    where ".." is a complete path segment, then replace that
            //    prefix with "/" in the input buffer and remove the last
            //    segment and its preceding "/" (if any) from the output
            //    buffer; otherwise,
            if ((rpos + 2 < len) && (data[rpos] == '.') && (data[rpos + 1] == '.') && (data[rpos + 2] == '/')) {
                c = '/';
                rpos += 3;

                // Remove the last segment
                while ((wpos > 0) && (data[wpos - 1] != '/')) wpos--;
                if (wpos > 0) wpos--;
                continue;
            } else if ((rpos + 2 == len) && (data[rpos] == '.') && (data[rpos + 1] == '.')) {
                c = '/';
                rpos += 2;

                // Remove the last segment
                while ((wpos > 0) && (data[wpos - 1] != '/')) wpos--;
                if (wpos > 0) wpos--;
                continue;
            }
        }

        // D.  if the input buffer consists only of "." or "..", then remove
        // that from the input buffer; otherwise,
        if ((c == '.') && (rpos == len)) {
            rpos++;
            continue;
        }

        if ((c == '.') && (rpos + 1 == len) && (data[rpos] == '.')) {
            rpos += 2;
            continue;
        }

        // E.  move the first path segment in the input buffer to the end of
        // the output buffer, including the initial "/" character (if
        // any) and any subsequent characters up to, but not including,
        // the next "/" character or the end of the input buffer.
        data[wpos++] = c;

        while ((rpos < len) && (data[rpos] != '/') && (wpos < len)) {
            data[wpos++] = data[rpos++];
        }

        c = -1;
    }

    bstr_adjust_len(s, wpos);
}

/**
 *
 */
void fprint_bstr(FILE *stream, const char *name, bstr *b) {
    if (b == NULL) {
        fprint_raw_data_ex(stream, name, "(null)", 0, 6);
        return;
    }

    fprint_raw_data_ex(stream, name, bstr_ptr(b), 0, bstr_len(b));
}

/**
 *
 */
void fprint_raw_data(FILE *stream, const char *name, const void *data, size_t len) {
    fprint_raw_data_ex(stream, name, data, 0, len);
}

/**
 *
 */
void fprint_raw_data_ex(FILE *stream, const char *name, const void *_data, size_t offset, size_t printlen) {
    const unsigned char *data = (const unsigned char *) _data;
    char buf[160];
    size_t len = offset + printlen;

    fprintf(stream, "\n%s: ptr %p offset %u len %u\n", name, (void*) data, (unsigned int)offset, (unsigned int)len);

    while (offset < len) {
        size_t i;

        snprintf(buf, sizeof(buf), "%x" PRIx64, (unsigned int) offset);
        strlcat(buf, "  ", sizeof(buf));

        i = 0;
        while (i < 8) {
            if (offset + i < len) {
                char step[4];
                snprintf(step, sizeof(step), "%02x ", data[offset + i]);
                strlcat(buf, step, sizeof(buf));
            } else {
                strlcat(buf, "   ", sizeof(buf));
            }

            i++;
        }

        strlcat(buf, " ", sizeof(buf));

        i = 8;
        while (i < 16) {
            if (offset + i < len) {
                char step[4];
                snprintf(step, sizeof(step), "%02x ", data[offset + i]);
                strlcat(buf, step, sizeof(buf));
            } else {
                strlcat(buf, "   ", sizeof(buf));
            }

            i++;
        }

        strlcat(buf, " |", sizeof(buf));

        i = 0;
        char *p = buf + strlen(buf);
        while ((offset + i < len) && (i < 16)) {
            int c = data[offset + i];

            if (isprint(c)) {
                *p++ = c;
            } else {
                *p++ = '.';
            }

            i++;
        }

        *p++ = '|';
        *p++ = '\n';
        *p = '\0';

        fprintf(stream, "%s", buf);
        offset += 16;
    }

    fprintf(stream, "\n");
}

/**
 *
 */
char *htp_connp_in_state_as_string(htp_connp_t *connp) {
    if (connp == NULL) return "NULL";

    if (connp->in_state == htp_connp_REQ_IDLE) return "REQ_IDLE";
    if (connp->in_state == htp_connp_REQ_LINE) return "REQ_LINE";
    if (connp->in_state == htp_connp_REQ_PROTOCOL) return "REQ_PROTOCOL";
    if (connp->in_state == htp_connp_REQ_HEADERS) return "REQ_HEADERS";
    if (connp->in_state == htp_connp_REQ_CONNECT_CHECK) return "REQ_CONNECT_CHECK";
    if (connp->in_state == htp_connp_REQ_CONNECT_WAIT_RESPONSE) return "REQ_CONNECT_WAIT_RESPONSE";
    if (connp->in_state == htp_connp_REQ_BODY_DETERMINE) return "REQ_BODY_DETERMINE";
    if (connp->in_state == htp_connp_REQ_BODY_IDENTITY) return "REQ_BODY_IDENTITY";
    if (connp->in_state == htp_connp_REQ_BODY_CHUNKED_LENGTH) return "REQ_BODY_CHUNKED_LENGTH";
    if (connp->in_state == htp_connp_REQ_BODY_CHUNKED_DATA) return "REQ_BODY_CHUNKED_DATA";
    if (connp->in_state == htp_connp_REQ_BODY_CHUNKED_DATA_END) return "REQ_BODY_CHUNKED_DATA_END";
    if (connp->in_state == htp_connp_REQ_FINALIZE) return "REQ_FINALIZE";
    if (connp->in_state == htp_connp_REQ_IGNORE_DATA_AFTER_HTTP_0_9) return "REQ_IGNORE_DATA_AFTER_HTTP_0_9";

    return "UNKNOWN";
}

/**
 *
 */
char *htp_connp_out_state_as_string(htp_connp_t *connp) {
    if (connp == NULL) return "NULL";

    if (connp->out_state == htp_connp_RES_IDLE) return "RES_IDLE";
    if (connp->out_state == htp_connp_RES_LINE) return "RES_LINE";
    if (connp->out_state == htp_connp_RES_HEADERS) return "RES_HEADERS";
    if (connp->out_state == htp_connp_RES_BODY_DETERMINE) return "RES_BODY_DETERMINE";
    if (connp->out_state == htp_connp_RES_BODY_IDENTITY_CL_KNOWN) return "RES_BODY_IDENTITY_CL_KNOWN";
    if (connp->out_state == htp_connp_RES_BODY_IDENTITY_STREAM_CLOSE) return "RES_BODY_IDENTITY_STREAM_CLOSE";
    if (connp->out_state == htp_connp_RES_BODY_CHUNKED_LENGTH) return "RES_BODY_CHUNKED_LENGTH";
    if (connp->out_state == htp_connp_RES_BODY_CHUNKED_DATA) return "RES_BODY_CHUNKED_DATA";
    if (connp->out_state == htp_connp_RES_BODY_CHUNKED_DATA_END) return "RES_BODY_CHUNKED_DATA_END";
    if (connp->out_state == htp_connp_RES_FINALIZE) return "RES_BODY_FINALIZE";

    return "UNKNOWN";
}

/**
 *
 */
char *htp_tx_request_progress_as_string(htp_tx_t *tx) {
    if (tx == NULL) return "NULL";

    switch (tx->request_progress) {
        case HTP_REQUEST_NOT_STARTED:
            return "NOT_STARTED";
        case HTP_REQUEST_LINE:
            return "REQ_LINE";
        case HTP_REQUEST_HEADERS:
            return "REQ_HEADERS";
        case HTP_REQUEST_BODY:
            return "REQ_BODY";
        case HTP_REQUEST_TRAILER:
            return "REQ_TRAILER";
        case HTP_REQUEST_COMPLETE:
            return "COMPLETE";
    }

    return "INVALID";
}

/**
 *
 */
char *htp_tx_response_progress_as_string(htp_tx_t *tx) {
    if (tx == NULL) return "NULL";

    switch (tx->response_progress) {
        case HTP_RESPONSE_NOT_STARTED:
            return "NOT_STARTED";
        case HTP_RESPONSE_LINE:
            return "RES_LINE";
        case HTP_RESPONSE_HEADERS:
            return "RES_HEADERS";
        case HTP_RESPONSE_BODY:
            return "RES_BODY";
        case HTP_RESPONSE_TRAILER:
            return "RES_TRAILER";
        case HTP_RESPONSE_COMPLETE:
            return "COMPLETE";
    }

    return "INVALID";
}

bstr *htp_unparse_uri_noencode(htp_uri_t *uri) {
    if (uri == NULL) return NULL;    

    // On the first pass determine the length of the final string
    size_t len = 0;

    if (uri->scheme != NULL) {
        len += bstr_len(uri->scheme);
        len += 3; // "://"
    }

    if ((uri->username != NULL) || (uri->password != NULL)) {
        if (uri->username != NULL) {
            len += bstr_len(uri->username);
        }

        len += 1; // ":"

        if (uri->password != NULL) {
            len += bstr_len(uri->password);
        }

        len += 1; // "@"
    }

    if (uri->hostname != NULL) {
        len += bstr_len(uri->hostname);
    }

    if (uri->port != NULL) {
        len += 1; // ":"
        len += bstr_len(uri->port);
    }

    if (uri->path != NULL) {
        len += bstr_len(uri->path);
    }

    if (uri->query != NULL) {
        len += 1; // "?"
        len += bstr_len(uri->query);
    }

    if (uri->fragment != NULL) {
        len += 1; // "#"
        len += bstr_len(uri->fragment);
    }

    // On the second pass construct the string
    bstr *r = bstr_alloc(len);
    if (r == NULL) return NULL;    

    if (uri->scheme != NULL) {
        bstr_add_noex(r, uri->scheme);
        bstr_add_c_noex(r, "://");
    }

    if ((uri->username != NULL) || (uri->password != NULL)) {
        if (uri->username != NULL) {
            bstr_add_noex(r, uri->username);
        }

        bstr_add_c_noex(r, ":");

        if (uri->password != NULL) {
            bstr_add_noex(r, uri->password);
        }

        bstr_add_c_noex(r, "@");
    }

    if (uri->hostname != NULL) {
        bstr_add_noex(r, uri->hostname);
    }

    if (uri->port != NULL) {
        bstr_add_c_noex(r, ":");
        bstr_add_noex(r, uri->port);
    }

    if (uri->path != NULL) {
        bstr_add_noex(r, uri->path);
    }

    if (uri->query != NULL) {
        bstr_add_c_noex(r, "?");
        bstr_add_noex(r, uri->query);

        /*
        bstr *query = bstr_dup(uri->query);
        if (query == NULL) {
            bstr_free(r);
            return NULL;
        }

        htp_uriencoding_normalize_inplace(query);

        bstr_add_c_noex(r, "?");
        bstr_add_noex(r, query);

        bstr_free(query);
        */
    }

    if (uri->fragment != NULL) {
        bstr_add_c_noex(r, "#");
        bstr_add_noex(r, uri->fragment);
    }

    return r;
}

/**
 * Determine if the information provided on the response line
 * is good enough. Browsers are lax when it comes to response
 * line parsing. In most cases they will only look for the
 * words "http" at the beginning.
 *
 * @param[in] data pointer to bytearray
 * @param[in] len length in bytes of data
 * @return 1 for good enough or 0 for not good enough
 */
int htp_treat_response_line_as_body(const uint8_t *data, size_t len) {
    // Browser behavior:
    //      Firefox 3.5.x: (?i)^\s*http
    //      IE: (?i)^\s*http\s*/
    //      Safari: ^HTTP/\d+\.\d+\s+\d{3}

    if (data == NULL) return 1;
    if (len < 4) return 1;

    if ((data[0] != 'H') && (data[0] != 'h')) return 1;
    if ((data[1] != 'T') && (data[1] != 't')) return 1;
    if ((data[2] != 'T') && (data[2] != 't')) return 1;
    if ((data[3] != 'P') && (data[3] != 'p')) return 1;

    return 0;
}

/**
 * Run the REQUEST_BODY_DATA hook.
 *
 * @param[in] connp
 * @param[in] d
 */
htp_status_t htp_req_run_hook_body_data(htp_connp_t *connp, htp_tx_data_t *d) {
    // Do not invoke callbacks with an empty data chunk
    if ((d->data != NULL) && (d->len == 0)) return HTP_OK;

    // Do not invoke callbacks without a transaction.
    if (connp->in_tx == NULL) return HTP_OK;

    // Run transaction hooks first
    htp_status_t rc = htp_hook_run_all(connp->in_tx->hook_request_body_data, d);
    if (rc != HTP_OK) return rc;

    // Run configuration hooks second
    rc = htp_hook_run_all(connp->cfg->hook_request_body_data, d);
    if (rc != HTP_OK) return rc;

    // On PUT requests, treat request body as file
    if (connp->put_file != NULL) {
        htp_file_data_t file_data;

        file_data.data = d->data;
        file_data.len = d->len;
        file_data.file = connp->put_file;
        file_data.file->len += d->len;

        rc = htp_hook_run_all(connp->cfg->hook_request_file_data, &file_data);
        if (rc != HTP_OK) return rc;
    }

    return HTP_OK;
}

/**
 * Run the RESPONSE_BODY_DATA hook.
 *
 * @param[in] connp
 * @param[in] d
 */
htp_status_t htp_res_run_hook_body_data(htp_connp_t *connp, htp_tx_data_t *d) {
    // Do not invoke callbacks with an empty data chunk.
    if ((d->data != NULL) && (d->len == 0)) return HTP_OK;

    // Run transaction hooks first
    htp_status_t rc = htp_hook_run_all(connp->out_tx->hook_response_body_data, d);
    if (rc != HTP_OK) return rc;

    // Run configuration hooks second
    rc = htp_hook_run_all(connp->cfg->hook_response_body_data, d);
    if (rc != HTP_OK) return rc;

    return HTP_OK;
}

/**
 * Parses the provided memory region, extracting the double-quoted string.
 *
 * @param[in] data
 * @param[in] len
 * @param[out] out
 * @param[out] endoffset
 * @return HTP_OK on success, HTP_DECLINED if the input is not well formed, and HTP_ERROR on fatal errors.
 */
htp_status_t htp_extract_quoted_string_as_bstr(unsigned char *data, size_t len, bstr **out, size_t *endoffset) {
    if ((data == NULL) || (out == NULL)) return HTP_ERROR;

    if (len == 0) return HTP_DECLINED;

    size_t pos = 0;

    // Check that the first character is a double quote.
    if (data[pos] != '"') return HTP_DECLINED;

    // Step over the double quote.
    pos++;
    if (pos == len) return HTP_DECLINED;

    // Calculate the length of the resulting string.
    size_t escaped_chars = 0;
    while (pos < len) {
        if (data[pos] == '\\') {
            if (pos + 1 < len) {
                escaped_chars++;
                pos += 2;
                continue;
            }
        } else if (data[pos] == '"') {
            break;
        }

        pos++;
    }

    // Have we reached the end of input without seeing the terminating double quote?
    if (pos == len) return HTP_DECLINED;

    // Copy the data and unescape it as necessary.
    size_t outlen = pos - 1 - escaped_chars;
    *out = bstr_alloc(outlen);
    if (*out == NULL) return HTP_ERROR;
    unsigned char *outptr = bstr_ptr(*out);
    size_t outpos = 0;

    pos = 1;
    while ((pos < len) && (outpos < outlen)) {
        // TODO We are not properly unescaping test here, we're only
        //      handling escaped double quotes.
        if (data[pos] == '\\') {
            if (pos + 1 < len) {
                outptr[outpos++] = data[pos + 1];
                pos += 2;
                continue;
            }
        } else if (data[pos] == '"') {
            break;
        }

        outptr[outpos++] = data[pos++];
    }

    bstr_adjust_len(*out, outlen);

    if (endoffset != NULL) {
        *endoffset = pos;
    }

    return HTP_OK;
}

htp_status_t htp_parse_ct_header(bstr *header, bstr **ct) {
    if ((header == NULL) || (ct == NULL)) return HTP_ERROR;

    unsigned char *data = bstr_ptr(header);
    size_t len = bstr_len(header);

    // The assumption here is that the header value we receive
    // here has been left-trimmed, which means the starting position
    // is on the media type. On some platforms that may not be the
    // case, and we may need to do the left-trim ourselves.

    // Find the end of the MIME type, using the same approach PHP 5.4.3 uses.
    size_t pos = 0;
    while ((pos < len) && (data[pos] != ';') && (data[pos] != ',') && (data[pos] != ' ')) pos++;

    *ct = bstr_dup_ex(header, 0, pos);
    if (*ct == NULL) return HTP_ERROR;

    bstr_to_lowercase(*ct);

    return HTP_OK;
}

/**
 * Implements relaxed (not strictly RFC) hostname validation.
 * 
 * @param[in] hostname
 * @return 1 if the supplied hostname is valid; 0 if it is not.
 */
int htp_validate_hostname(bstr *hostname) {
    unsigned char *data = bstr_ptr(hostname);
    size_t len = bstr_len(hostname);
    size_t startpos = 0;
    size_t pos = 0;

    if ((len == 0) || (len > 255)) return 0;

    while (pos < len) {
        // Validate label characters.
        startpos = pos;
        while ((pos < len) && (data[pos] != '.')) {
            unsigned char c = data[pos];
            // According to the RFC, the underscore is not allowed in a label, but
            // we allow it here because we think it's often seen in practice.
            if (!(((c >= 'a') && (c <= 'z')) || ((c >= 'A') && (c <= 'Z')) ||
                        ((c >= '0') && (c <= '9')) ||
                         (c == '-') || (c == '_')))
            {
                return 0;
            }

            pos++;
        }

        // Validate label length.
        if ((pos - startpos == 0) || (pos - startpos > 63)) return 0;

        if (pos >= len) return 1; // No more data after label.

        // How many dots are there?
        startpos = pos;
        while ((pos < len) && (data[pos] == '.')) pos++;

        if (pos - startpos != 1) return 0; // Exactly one dot expected.
    }

    return 1;
}

void htp_uri_free(htp_uri_t *uri) {
    if (uri == NULL) return;

    bstr_free(uri->scheme);
    bstr_free(uri->username);
    bstr_free(uri->password);
    bstr_free(uri->hostname);
    bstr_free(uri->port);
    bstr_free(uri->path);
    bstr_free(uri->query);
    bstr_free(uri->fragment);

    free(uri);
}

htp_uri_t *htp_uri_alloc() {
    htp_uri_t *u = calloc(1, sizeof (htp_uri_t));
    if (u == NULL) return NULL;

    u->port_number = -1;

    return u;
}

char *htp_get_version(void) {
    return HTP_VERSION_STRING_FULL;
}
