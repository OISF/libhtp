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
 * @author Christopher Alfeld <calfeld@qualys.com>
 */

#include <ruby.h>
#include <htp/htp.h>

/* Status
 * Complete: Tx, Header, HeaderLine, URI, all numeric constants.
 * Incomplete: Cfg, Connp
 * Missing completely: file, file_data, log, tx_data (probably not needed)
 */

// Debug
#ifdef RBHTP_DBEUG
#include <stdio.h>
#define P( value ) { VALUE inspect = rb_funcall( value, rb_intern( "inspect" ), 0 ); printf("%s\n",StringValueCStr(inspect)); }
#else
#define P( value )
#endif

static VALUE mHTP;
static VALUE cCfg;
static VALUE cConnp;
static VALUE cTx;
static VALUE cHeader;
static VALUE cHeaderLine;
static VALUE cURI;
static VALUE cFile;
static VALUE cConn;

#define BSTR_TO_RSTR( B ) ( rb_str_new( bstr_ptr( B ), bstr_len( B ) ) )

// Accessor Helpers
#define RBHTP_R_INT( T, N ) \
  VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
  { \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		return INT2FIX( x->N ); \
  }

#define RBHTP_R_TV( T, N ) \
	VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
	{ \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		return rb_time_new( x->N.tv_sec, x->N.tv_usec ); \
	}

#define RBHTP_R_CSTR( T, N ) \
  VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
  { \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		if ( x->N == NULL ) return Qnil; \
		return rb_str_new2( x->N ); \
  }

#define RBHTP_W_INT( T, N ) \
	VALUE rbhtp_## T ##_ ## N ## _set( VALUE self, VALUE v ) \
	{ \
		Check_Type( v, T_FIXNUM ); \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		x->N = FIX2INT( v ); \
		return Qnil; \
	}
	
#define RBHTP_RW_INT( T, N ) \
	RBHTP_R_INT( T, N ) \
	RBHTP_W_INT( T, N )

#define RBHTP_R_BOOL( T, N ) \
  VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
  { \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		return x->N == 1 ? Qtrue : Qfalse; \
  }

#define RBHTP_R_STRING( T, N ) \
	VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
	{ \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		if ( x->N == NULL ) \
			return Qnil; \
		return BSTR_TO_RSTR( x->N ); \
	}
	
#define RBHTP_R_HTP( T, N, H ) \
	VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
	{ \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		if ( x->N == NULL ) \
			return Qnil; \
		return rb_funcall( H, rb_intern( "new" ), 1, \
			Data_Wrap_Struct( rb_cObject, 0, 0, x->N ) ); \
	}

#define RBHTP_R_URI( T, N ) RBHTP_R_HTP( T, N, cURI )
	
static VALUE rbhtp_r_string_table( htp_table_t* table )
{
	if ( table == NULL ) return Qnil;
	
	bstr *k, *v;
	VALUE r = rb_ary_new();	
    for (int i = 0, n = htp_table_size(table); i < n; i++) {
        v = htp_table_get_index(table, i, &k);
		rb_ary_push( r, rb_ary_new3( 2,
			BSTR_TO_RSTR( *k ), BSTR_TO_RSTR( *v ) ) );
	}
	return r;
}
	
#define RBHTP_R_STRING_TABLE( T, N ) \
	VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
	{ \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		return rbhtp_r_string_table( x->N ); \
	}

// We don't push the keys as they are duplicated in the header.
static VALUE rbhtp_r_header_table( htp_table_t* table )
{
	if ( table == NULL ) return Qnil; 	
	htp_header_t* v; 
	VALUE r = rb_ary_new(); 

    for (int i = 0, n = htp_table_size(table); i < n; i++) {
        v = htp_table_get_index(table, i, NULL);
        rb_ary_push( r,
			rb_funcall( cHeader, rb_intern( "new" ), 1,
				Data_Wrap_Struct( rb_cObject, 0, 0, v ) ) );
    }

	return r; 
}	

#define RBHTP_R_HEADER_TABLE( T, N ) \
	VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
	{ \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		return rbhtp_r_header_table( x->N ); \
	}

static VALUE rbhtp_r_header_line_list( htp_list_t* list )
{
	if ( list == NULL ) return Qnil;	
	VALUE r = rb_ary_new();	
    for (int i = 0, n = htp_list_size(list); i < n; i++) {
        htp_header_line_t *v = htp_list_get(list, i);
        
		rb_ary_push( r, 
			rb_funcall( cHeaderLine, rb_intern( "new" ), 1,
				Data_Wrap_Struct( rb_cObject, 0, 0, v ) ) );
	}
	return r;
}

#define RBHTP_R_HEADER_LINE_LIST( T, N ) \
	VALUE rbhtp_ ## T ## _ ## N( VALUE self ) \
	{ \
		htp_ ## T ## _t* x = NULL; \
		Data_Get_Struct( rb_iv_get( self, "@" #T ), htp_ ## T ## _t, x ); \
		return rbhtp_r_header_line_list( x->N ); \
	}

// This function is only needed when we malloc the URI ourselves.
void rbhtp_free_uri( void* p )
{
	htp_uri_t* uri = (htp_uri_t*)p;
	free( uri );
}

//---- HTP ---
VALUE rbhtp_get_version( VALUE self )
{
	return rb_str_new2( htp_get_version() );
}

// We return a HTP::URI and throw an exception on error.
VALUE rbhtp_parse_uri( VALUE self, VALUE input )
{
	Check_Type( input, T_STRING );
	bstr* input_b = bstr_dup_mem( RSTRING_PTR( input ), RSTRING_LEN( input ) );
	htp_uri_t* uri = NULL; // htp_parse_uri will alloc.
	
	int result = htp_parse_uri( input_b, &uri );
	if ( result != HTP_OK ) {
		bstr_free( input_b );
		free( uri );
		rb_raise( rb_eRuntimeError, "HTP error in htp_parse_uri: %d", result );
		return Qnil; // Ignored?
	}

	bstr_free( input_b ); // Okay, as htp_parse_uri dups the data it needs.

	return rb_funcall( cURI, rb_intern( "new" ), 1,
		Data_Wrap_Struct( rb_cObject, 0, rbhtp_free_uri, uri )
	);
}

//---- Cfg ----

// Terminate list with "".
static char* const rbhtp_config_pvars[] = {
	"@request_proc", 
	"@request_proc",
	"@transaction_start",
	"@request_line",
	"@request_headers",
	"@request_trailer",
	"@response_line",
	"@response_headers",
	"@response_trailers",
	""
};

void rbhtp_config_free( void* p )
{
	htp_cfg_t* cfg = (htp_cfg_t*)p;
	htp_config_destroy( cfg );
}

VALUE rbhtp_config_initialize( VALUE self )
{
	char* const* v = &rbhtp_config_pvars[0];
	while ( *v[0] != '\0' ) {
		rb_iv_set( self, *v, Qnil );
		++v;
	}
	
	htp_cfg_t* cfg = htp_config_create();

	rb_iv_set( self, "@cfg", 
		Data_Wrap_Struct( rb_cObject, 0, rbhtp_config_free, cfg ) 
	);
	
	return Qnil;
}

VALUE rbhtp_config_copy( VALUE self )
{
	// We create one too many copies here.
	VALUE new_config = rb_funcall( cCfg, rb_intern( "new" ), 0 );
	htp_cfg_t* cfg = NULL;
	Data_Get_Struct( rb_iv_get( self, "@cfg" ), htp_cfg_t, cfg );

	// Note that the existing new_config @cfg will be garbage collected as a 
	// result of this set.
	
	rb_iv_set( new_config, "@cfg", 
		Data_Wrap_Struct( rb_cObject, 0, rbhtp_config_free, 
			htp_config_copy( cfg ) ) );
			
	// Now copy over all our callbacks.
	char* const* v = &rbhtp_config_pvars[0];
	while ( *v[0] != '\0' ) {
		rb_iv_set( new_config, *v, rb_iv_get( self, *v ) );
		++v;
	}

	return new_config;
}

VALUE rbhtp_config_set_server_personality( VALUE self, VALUE personality )
{
	Check_Type( personality, T_FIXNUM );
	
	htp_cfg_t* cfg = NULL;
	Data_Get_Struct( rb_iv_get( self, "@cfg" ), htp_cfg_t, cfg );

	return INT2FIX( 
		htp_config_set_server_personality( cfg, FIX2INT( personality ) ) 
	);
}

VALUE rbhtp_config_register_urlencoded_parser( VALUE self )
{
	htp_cfg_t* cfg = NULL;
	Data_Get_Struct( rb_iv_get( self, "@cfg" ), htp_cfg_t, cfg );

	htp_config_register_urlencoded_parser( cfg );

	return Qnil;
}	

#define RBHTP_CALLBACK_SUB( N ) \
	VALUE rbhtp_config_register_ ## N( VALUE self ) \
	{ \
		if ( ! rb_block_given_p() ) { \
			rb_raise( rb_eArgError, "A block is required." ); \
			return Qnil; \
		} \
		VALUE proc = rb_iv_get( self, "@" #N "_proc" ); \
		if ( proc == Qnil ) { \
			htp_cfg_t* cfg = NULL; \
			Data_Get_Struct( rb_iv_get( self, "@cfg" ), htp_cfg_t, cfg ); \
			htp_config_register_## N( cfg, rbhtp_config_callback_ ## N ); \
		} \
		rb_iv_set( self, "@" #N "_proc", rb_block_proc() ); \
		return self; \
	}
	
#define RBHTP_CONNP_CALLBACK( N ) \
	int rbhtp_config_callback_ ## N( htp_connp_t* connp ) \
	{ \
		VALUE userdata = (VALUE)htp_connp_get_user_data( connp ); \
		VALUE config = rb_iv_get( userdata, "@cfg" ); \
		VALUE proc = rb_iv_get( config, "@" #N "_proc" ); \
		if ( proc != Qnil ) { \
			return INT2FIX( \
				rb_funcall( proc, rb_intern( "call" ), 1, userdata )  \
			); \
		} \
		return 1; \
	} \
	RBHTP_CALLBACK_SUB( N )
	
// Tx data is a tx and a data block.  For *_body_data callbacks we pass 
// in the tx as first argument and the data as a string as the second argument.
#define RBHTP_TXDATA_CALLBACK( N ) \
	int rbhtp_config_callback_ ##N( htp_tx_data_t* txdata ) \
	{ \
		htp_connp_t* connp = txdata->tx->connp; \
		VALUE userdata = (VALUE)htp_connp_get_user_data( connp ); \
		VALUE config = rb_iv_get( userdata, "@cfg" ); \
		VALUE proc = rb_iv_get( config, "@" #N "_proc" ); \
		if ( proc != Qnil ) { \
			VALUE data = Qnil; \
			if ( txdata->data ) \
				data = rb_str_new( (char*)txdata->data, txdata->len ); \
			return INT2FIX( \
				rb_funcall( proc, rb_intern( "call" ), 2, \
					rb_funcall( cTx, rb_intern( "new" ), 3,  \
						Data_Wrap_Struct( rb_cObject, 0, 0, txdata->tx ), \
						config, \
						userdata \
					), \
					data \
			  ) \
			); \
		} \
		return 1; \
	} \
	RBHTP_CALLBACK_SUB( N )
		
		
RBHTP_CONNP_CALLBACK( request )
RBHTP_CONNP_CALLBACK( response )
RBHTP_CONNP_CALLBACK( transaction_start )
RBHTP_CONNP_CALLBACK( request_line )
RBHTP_CONNP_CALLBACK( request_headers )
RBHTP_CONNP_CALLBACK( request_trailer )
RBHTP_CONNP_CALLBACK( response_line )
RBHTP_CONNP_CALLBACK( response_headers )
RBHTP_CONNP_CALLBACK( response_trailer )

RBHTP_TXDATA_CALLBACK( request_body_data )
RBHTP_TXDATA_CALLBACK( response_body_data )

RBHTP_R_INT( cfg, spersonality )
RBHTP_RW_INT( cfg, parse_request_cookies )

// File data is a tx, file information, and file data.  The callback thus
// takes those three as arguments.
int rbhtp_config_callback_request_file_data( htp_file_data_t* filedata )
{
	htp_connp_t* connp = filedata->tx->connp;
	VALUE userdata = (VALUE)htp_connp_get_user_data( connp );
	VALUE config = rb_iv_get( userdata, "@cfg" );
	VALUE proc = rb_iv_get( config, "@request_file_data_proc" );
	if ( proc != Qnil ) {
		VALUE data = Qnil;
		if ( filedata->data )
			data = rb_str_new( (char*)filedata->data, filedata->len );
		return INT2FIX(
			rb_funcall( proc, rb_intern( "call" ), 2,
				rb_funcall( cTx, rb_intern( "new" ), 1, 
					Data_Wrap_Struct( rb_cObject, 0, 0, filedata->tx )
				),
				rb_funcall( cFile, rb_intern( "new" ), 1, 
					Data_Wrap_Struct( rb_cObject, 0, 0, filedata->file )
				),
				data
		  )
		);
	}
	return 1;
}
RBHTP_CALLBACK_SUB( request_file_data )

//---- Connp ----

void rbhtp_connp_free( void* p )
{
	htp_connp_t* connp = (htp_connp_t*)p;
	if ( connp )
		htp_connp_destroy_all( connp );
}

VALUE rbhtp_connp_initialize( VALUE self, VALUE config )
{
	rb_iv_set( self, "@cfg", config );
	
	htp_cfg_t* cfg = NULL;
	Data_Get_Struct( rb_iv_get( config, "@cfg" ), htp_cfg_t, cfg );
	
	htp_connp_t* connp = htp_connp_create( cfg );
	htp_connp_set_user_data( connp, (void*)self );
	rb_iv_set( self, "@connp", 
		Data_Wrap_Struct( rb_cObject, 0, rbhtp_connp_free, connp ) 
	);
	
	return Qnil;
}

VALUE rbhtp_connp_req_data( VALUE self, VALUE timestamp, VALUE data )
{
	if ( strncmp( "Time", rb_class2name( CLASS_OF( timestamp ) ), 4 ) != 0 ) {
		rb_raise( rb_eTypeError, "First argument must be a Time." );
		return Qnil;
	}

	StringValue( data ); // try to make data a string.	
	Check_Type( data, T_STRING );
	
	size_t len = RSTRING_LEN( data );
	char* data_c = RSTRING_PTR( data );

	htp_time_t timestamp_c;
	timestamp_c.tv_sec = 
		FIX2INT( rb_funcall( timestamp, rb_intern( "tv_sec" ), 0 ) );
	timestamp_c.tv_usec = 
		FIX2INT( rb_funcall( timestamp, rb_intern( "tv_usec" ), 0 ) );

	VALUE connp_r = rb_iv_get( self, "@connp" );
	htp_connp_t* connp = NULL;
	Data_Get_Struct( connp_r, htp_connp_t, connp );
		
	int result = 
		htp_connp_req_data( connp, &timestamp_c, (unsigned char*)data_c, len );
	
	return INT2FIX( result );
}

VALUE rbhtp_connp_in_tx( VALUE self )
{
	VALUE connp_r = rb_iv_get( self, "@connp" );
	VALUE config = rb_iv_get( self, "@cfg" );
	htp_connp_t* connp = NULL;
	Data_Get_Struct( connp_r, htp_connp_t, connp );
	
	if ( connp->in_tx == NULL )
		return Qnil;
	
	return rb_funcall( cTx, rb_intern( "new" ), 3, 
		Data_Wrap_Struct( rb_cObject, 0, 0, connp->in_tx ),
		config, 
		self
	);
}

VALUE rbhtp_connp_conn( VALUE self )
{
	htp_connp_t* connp = NULL;
	Data_Get_Struct( rb_iv_get( self, "@connp" ), htp_connp_t, connp );
	if ( connp->conn == NULL )
		return Qnil;
	return rb_funcall( cConn, rb_intern( "new" ), 2,
		Data_Wrap_Struct( rb_cObject, 0, 0, connp->conn ),
		self
	);
}

// Unlike Connp and Cfg, these are just wrapper.  The lifetime of the
// underlying objects are bound to the Connp.

//---- Header ----
VALUE rbhtp_header_initialize( VALUE self, VALUE raw_header )
{
	rb_iv_set( self, "@header", raw_header );
	return Qnil;
}

RBHTP_R_STRING( header, name );
RBHTP_R_STRING( header, value );
RBHTP_R_INT( header, flags );

// ---- Header Line ----
VALUE rbhtp_header_line_initialize( VALUE self, VALUE raw_header_line )
{
	rb_iv_set( self, "@header_line", raw_header_line );
	return Qnil;
}

VALUE rbhtp_header_line_header( VALUE self )
{
	htp_header_line_t* hline = NULL;
	Data_Get_Struct( rb_iv_get( self, "@header_line" ), htp_header_line_t, hline );
	
	if ( hline->header == NULL ) 
		return Qnil;
		
	return rb_funcall( cHeader, rb_intern( "new" ), 1,
		Data_Wrap_Struct( rb_cObject, 0, 0, hline->header )
	);	
}

RBHTP_R_STRING( header_line, line );
RBHTP_R_INT( header_line, name_offset );
RBHTP_R_INT( header_line, name_len );
RBHTP_R_INT( header_line, value_offset );
RBHTP_R_INT( header_line, value_len );
RBHTP_R_INT( header_line, has_nulls );
RBHTP_R_INT( header_line, first_nul_offset );
RBHTP_R_INT( header_line, flags );

// ---- URI ----
VALUE rbhtp_uri_initialize( VALUE self, VALUE raw_uri )
{
	rb_iv_set( self, "@uri", raw_uri );
	return Qnil;
}

RBHTP_R_STRING( uri, scheme );
RBHTP_R_STRING( uri, username );
RBHTP_R_STRING( uri, password );
RBHTP_R_STRING( uri, hostname );
RBHTP_R_STRING( uri, port );
RBHTP_R_INT( uri, port_number );
RBHTP_R_STRING( uri, path );
RBHTP_R_STRING( uri, query );
RBHTP_R_STRING( uri, fragment );

//---- Tx ----

VALUE rbhtp_tx_initialize( 
	VALUE self, 
	VALUE raw_txn, 
	VALUE cfg,
	VALUE connp )
{
	rb_iv_set( self, "@tx", raw_txn );
	rb_iv_set( self, "@cfg", cfg );
	rb_iv_set( self, "@connp", connp );
	
	return Qnil;
}

RBHTP_R_INT( tx, request_ignored_lines )
RBHTP_R_INT( tx, request_line_nul )
RBHTP_R_INT( tx, request_line_nul_offset )
RBHTP_R_INT( tx, request_method_number )
RBHTP_R_INT( tx, request_protocol_number )
RBHTP_R_INT( tx, protocol_is_simple )
RBHTP_R_INT( tx, request_message_len )
RBHTP_R_INT( tx, request_entity_len )
RBHTP_R_INT( tx, request_nonfiledata_len )
RBHTP_R_INT( tx, request_filedata_len )
RBHTP_R_INT( tx, request_header_lines_no_trailers )
RBHTP_R_INT( tx, request_headers_raw_lines )
RBHTP_R_INT( tx, request_transfer_coding )
RBHTP_R_INT( tx, request_content_encoding )
RBHTP_R_INT( tx, request_params_query_reused )
RBHTP_R_INT( tx, request_params_body_reused )
RBHTP_R_INT( tx, request_auth_type )
RBHTP_R_INT( tx, response_ignored_lines )
RBHTP_R_INT( tx, response_protocol_number )
RBHTP_R_INT( tx, response_status_number )
RBHTP_R_INT( tx, response_status_expected_number )
RBHTP_R_INT( tx, seen_100continue )
RBHTP_R_INT( tx, response_message_len )
RBHTP_R_INT( tx, response_entity_len )
RBHTP_R_INT( tx, response_transfer_coding )
RBHTP_R_INT( tx, response_content_encoding )
RBHTP_R_INT( tx, flags )
RBHTP_R_INT( tx, progress )

RBHTP_R_STRING( tx, request_method )
RBHTP_R_STRING( tx, request_line )
RBHTP_R_STRING( tx, request_uri )
RBHTP_R_STRING( tx, request_uri_normalized )
RBHTP_R_STRING( tx, request_protocol )
RBHTP_R_STRING( tx, request_headers_raw )
RBHTP_R_STRING( tx, request_headers_sep )
RBHTP_R_STRING( tx, request_content_type )
RBHTP_R_STRING( tx, request_auth_username )
RBHTP_R_STRING( tx, request_auth_password )
RBHTP_R_STRING( tx, response_line )
RBHTP_R_STRING( tx, response_protocol )
RBHTP_R_STRING( tx, response_status )
RBHTP_R_STRING( tx, response_message )
RBHTP_R_STRING( tx, response_headers_sep )

RBHTP_R_STRING_TABLE( tx, request_params_query )
RBHTP_R_STRING_TABLE( tx, request_params_body )
RBHTP_R_STRING_TABLE( tx, request_cookies )
RBHTP_R_HEADER_TABLE( tx, request_headers )
RBHTP_R_HEADER_TABLE( tx, response_headers )

RBHTP_R_HEADER_LINE_LIST( tx, request_header_lines );
RBHTP_R_HEADER_LINE_LIST( tx, response_header_lines );

RBHTP_R_URI( tx, parsed_uri )
RBHTP_R_URI( tx, parsed_uri_incomplete )

VALUE rbhtp_tx_conn( VALUE self )
{
	htp_tx_t* tx = NULL;
	Data_Get_Struct( rb_iv_get( self, "@tx" ), htp_tx_t, tx );
	if ( tx->conn == NULL )
		return Qnil;
	return rb_funcall( cConn, rb_intern( "new" ), 2,
		Data_Wrap_Struct( rb_cObject, 0, 0, tx->conn ),
		rb_iv_get( self, "@connp" )
	);
}

// ---- File ----
VALUE rbhtp_file_initialize( VALUE self, VALUE raw_file )
{
	rb_iv_set( self, "@file", raw_file );
	return Qnil;
}

RBHTP_R_INT( file, source )
RBHTP_R_STRING( file, filename )
RBHTP_R_INT( file, len )
RBHTP_R_CSTR( file, tmpname )
RBHTP_R_INT( file, fd )

// ---- Conn ----
VALUE rbhtp_conn_initialize( VALUE self, VALUE raw_conn, VALUE connp )
{
	rb_iv_set( self, "@conn", raw_conn );
	rb_iv_set( self, "@connp", connp );
	return Qnil;
}

RBHTP_R_CSTR( conn, remote_addr )
RBHTP_R_INT( conn, remote_port )
RBHTP_R_CSTR( conn, local_addr )
RBHTP_R_INT( conn, local_port )
RBHTP_R_INT( conn, flags )
RBHTP_R_INT( conn, in_data_counter )
RBHTP_R_INT( conn, out_data_counter )
RBHTP_R_INT( conn, in_packet_counter )
RBHTP_R_INT( conn, out_packet_counter )
RBHTP_R_TV( conn, open_timestamp )
RBHTP_R_TV( conn, close_timestamp )

VALUE rbhtp_conn_transactions( VALUE self )
{
	htp_conn_t* conn = NULL;
	Data_Get_Struct( rb_iv_get( self, "@conn" ), htp_conn_t, conn );
	
	if ( conn->transactions == NULL ) return Qnil;
	
	VALUE connp = rb_iv_get( self, "@connp" );
	VALUE cfg = rb_iv_get( connp, "@cfg" );
		
	VALUE r = rb_ary_new();
	
    for (int i = 0, n = htp_list_size(conn->transactions); i < n; i++) {
        htp_tx_t *v = htp_list_get(conn->transactions, i);
        
		rb_ary_push( r,
			rb_funcall( cTx, rb_intern( "new" ), 3,
				Data_Wrap_Struct( rb_cObject, 0, 0, v ),
				cfg,
				connp
			)
		);
	}
	return r;
}

//---- Init ----
void Init_htp( void )
{
	mHTP = rb_define_module( "HTP" );
	
	rb_define_singleton_method( mHTP, "get_version", rbhtp_get_version, 0 );
	rb_define_singleton_method( mHTP, "parse_uri", rbhtp_parse_uri, 1 );
	
	// All numeric constants from htp.h.
  rb_define_const( mHTP, "HTP_ERROR", INT2FIX( HTP_ERROR ) );
  rb_define_const( mHTP, "HTP_OK", INT2FIX( HTP_OK ) );
  rb_define_const( mHTP, "HTP_DATA", INT2FIX( HTP_DATA ) );
  rb_define_const( mHTP, "HTP_DATA_OTHER", INT2FIX( HTP_DATA_OTHER ) );
  rb_define_const( mHTP, "HTP_DECLINED", INT2FIX( HTP_DECLINED ) );
  rb_define_const( mHTP, "PROTOCOL_UNKNOWN", INT2FIX( HTP_PROTOCOL_UNKNOWN ) );
  rb_define_const( mHTP, "HTTP_0_9", INT2FIX( HTP_PROTOCOL_0_9 ) );
  rb_define_const( mHTP, "HTTP_1_0", INT2FIX( HTP_PROTOCOL_1_0 ) );
  rb_define_const( mHTP, "HTTP_1_1", INT2FIX( HTP_PROTOCOL_1_1 ) );
  rb_define_const( mHTP, "HTP_LOG_ERROR", INT2FIX( HTP_LOG_ERROR ) );
  rb_define_const( mHTP, "HTP_LOG_WARNING", INT2FIX( HTP_LOG_WARNING ) );
  rb_define_const( mHTP, "HTP_LOG_NOTICE", INT2FIX( HTP_LOG_NOTICE ) );
  rb_define_const( mHTP, "HTP_LOG_INFO", INT2FIX( HTP_LOG_INFO ) );
  rb_define_const( mHTP, "HTP_LOG_DEBUG", INT2FIX( HTP_LOG_DEBUG ) );
  rb_define_const( mHTP, "HTP_LOG_DEBUG2", INT2FIX( HTP_LOG_DEBUG2 ) );
  rb_define_const( mHTP, "HTP_HEADER_MISSING_COLON", INT2FIX( HTP_HEADER_MISSING_COLON ) );
  rb_define_const( mHTP, "HTP_HEADER_INVALID_NAME", INT2FIX( HTP_HEADER_INVALID_NAME ) );
  rb_define_const( mHTP, "HTP_HEADER_LWS_AFTER_FIELD_NAME", INT2FIX( HTP_HEADER_LWS_AFTER_FIELD_NAME ) );
  rb_define_const( mHTP, "HTP_LINE_TOO_LONG_HARD", INT2FIX( HTP_LINE_TOO_LONG_HARD ) );
  rb_define_const( mHTP, "HTP_LINE_TOO_LONG_SOFT", INT2FIX( HTP_LINE_TOO_LONG_SOFT ) );
  rb_define_const( mHTP, "HTP_HEADER_LIMIT_HARD", INT2FIX( HTP_HEADER_LIMIT_HARD ) );
  rb_define_const( mHTP, "HTP_HEADER_LIMIT_SOFT", INT2FIX( HTP_HEADER_LIMIT_SOFT ) );
  rb_define_const( mHTP, "HTP_VALID_STATUS_MIN", INT2FIX( HTP_VALID_STATUS_MIN ) );
  rb_define_const( mHTP, "HTP_VALID_STATUS_MAX", INT2FIX( HTP_VALID_STATUS_MAX ) );  
  rb_define_const( mHTP, "M_UNKNOWN", INT2FIX( M_UNKNOWN ) );
  rb_define_const( mHTP, "M_GET", INT2FIX( M_GET ) );
  rb_define_const( mHTP, "M_PUT", INT2FIX( M_PUT ) );
  rb_define_const( mHTP, "M_POST", INT2FIX( M_POST ) );
  rb_define_const( mHTP, "M_DELETE", INT2FIX( M_DELETE ) );
  rb_define_const( mHTP, "M_CONNECT", INT2FIX( M_CONNECT ) );
  rb_define_const( mHTP, "M_OPTIONS", INT2FIX( M_OPTIONS ) );
  rb_define_const( mHTP, "M_TRACE", INT2FIX( M_TRACE ) );
  rb_define_const( mHTP, "M_PATCH", INT2FIX( M_PATCH ) );
  rb_define_const( mHTP, "M_PROPFIND", INT2FIX( M_PROPFIND ) );
  rb_define_const( mHTP, "M_PROPPATCH", INT2FIX( M_PROPPATCH ) );
  rb_define_const( mHTP, "M_MKCOL", INT2FIX( M_MKCOL ) );
  rb_define_const( mHTP, "M_COPY", INT2FIX( M_COPY ) );
  rb_define_const( mHTP, "M_MOVE", INT2FIX( M_MOVE ) );
  rb_define_const( mHTP, "M_LOCK", INT2FIX( M_LOCK ) );
  rb_define_const( mHTP, "M_UNLOCK", INT2FIX( M_UNLOCK ) );
  rb_define_const( mHTP, "M_VERSION_CONTROL", INT2FIX( M_VERSION_CONTROL ) );
  rb_define_const( mHTP, "M_CHECKOUT", INT2FIX( M_CHECKOUT ) );
  rb_define_const( mHTP, "M_UNCHECKOUT", INT2FIX( M_UNCHECKOUT ) );
  rb_define_const( mHTP, "M_CHECKIN", INT2FIX( M_CHECKIN ) );
  rb_define_const( mHTP, "M_UPDATE", INT2FIX( M_UPDATE ) );
  rb_define_const( mHTP, "M_LABEL", INT2FIX( M_LABEL ) );
  rb_define_const( mHTP, "M_REPORT", INT2FIX( M_REPORT ) );
  rb_define_const( mHTP, "M_MKWORKSPACE", INT2FIX( M_MKWORKSPACE ) );
  rb_define_const( mHTP, "M_MKACTIVITY", INT2FIX( M_MKACTIVITY ) );
  rb_define_const( mHTP, "M_BASELINE_CONTROL", INT2FIX( M_BASELINE_CONTROL ) );
  rb_define_const( mHTP, "M_MERGE", INT2FIX( M_MERGE ) );
  rb_define_const( mHTP, "M_INVALID", INT2FIX( M_INVALID ) );
  rb_define_const( mHTP, "M_HEAD", INT2FIX( HTP_M_HEAD ) );
  rb_define_const( mHTP, "HTP_FIELD_UNPARSEABLE", INT2FIX( HTP_FIELD_UNPARSEABLE ) );
  rb_define_const( mHTP, "HTP_FIELD_INVALID", INT2FIX( HTP_FIELD_INVALID ) );
  rb_define_const( mHTP, "HTP_FIELD_FOLDED", INT2FIX( HTP_FIELD_FOLDED ) );
  rb_define_const( mHTP, "HTP_FIELD_REPEATED", INT2FIX( HTP_FIELD_REPEATED ) );
  rb_define_const( mHTP, "HTP_FIELD_LONG", INT2FIX( HTP_FIELD_LONG ) );
  rb_define_const( mHTP, "HTP_FIELD_NUL_BYTE", INT2FIX( HTP_FIELD_RAW_NUL ) );
  rb_define_const( mHTP, "HTP_REQUEST_SMUGGLING", INT2FIX( HTP_REQUEST_SMUGGLING ) );
  rb_define_const( mHTP, "HTP_INVALID_FOLDING", INT2FIX( HTP_INVALID_FOLDING ) );
  rb_define_const( mHTP, "HTP_INVALID_CHUNKING", INT2FIX( HTP_REQUEST_INVALID_T_E ) );
  rb_define_const( mHTP, "HTP_MULTI_PACKET_HEAD", INT2FIX( HTP_MULTI_PACKET_HEAD ) );
  rb_define_const( mHTP, "HTP_HOST_MISSING", INT2FIX( HTP_HOST_MISSING ) );
  rb_define_const( mHTP, "HTP_AMBIGUOUS_HOST", INT2FIX( HTP_HOST_AMBIGUOUS ) );
  rb_define_const( mHTP, "HTP_PATH_ENCODED_NUL", INT2FIX( HTP_PATH_ENCODED_NUL ) );
  rb_define_const( mHTP, "HTP_PATH_INVALID_ENCODING", INT2FIX( HTP_PATH_INVALID_ENCODING ) );
  rb_define_const( mHTP, "HTP_PATH_INVALID", INT2FIX( HTP_PATH_INVALID ) );
  rb_define_const( mHTP, "HTP_PATH_OVERLONG_U", INT2FIX( HTP_PATH_OVERLONG_U ) );
  rb_define_const( mHTP, "HTP_PATH_ENCODED_SEPARATOR", INT2FIX( HTP_PATH_ENCODED_SEPARATOR ) );
  rb_define_const( mHTP, "HTP_PATH_UTF8_VALID", INT2FIX( HTP_PATH_UTF8_VALID ) );
  rb_define_const( mHTP, "HTP_PATH_UTF8_INVALID", INT2FIX( HTP_PATH_UTF8_INVALID ) );
  rb_define_const( mHTP, "HTP_PATH_UTF8_OVERLONG", INT2FIX( HTP_PATH_UTF8_OVERLONG ) );
  rb_define_const( mHTP, "HTP_PATH_FULLWIDTH_EVASION", INT2FIX( HTP_PATH_HALF_FULL_RANGE ) );
  rb_define_const( mHTP, "HTP_STATUS_LINE_INVALID", INT2FIX( HTP_STATUS_LINE_INVALID ) );
  rb_define_const( mHTP, "PIPELINED_CONNECTION", INT2FIX( HTP_CONN_PIPELINED ) );
  rb_define_const( mHTP, "HTP_SERVER_MINIMAL", INT2FIX( HTP_SERVER_MINIMAL ) );
  rb_define_const( mHTP, "HTP_SERVER_GENERIC", INT2FIX( HTP_SERVER_GENERIC ) );
  rb_define_const( mHTP, "HTP_SERVER_IDS", INT2FIX( HTP_SERVER_IDS ) );
  rb_define_const( mHTP, "HTP_SERVER_IIS_4_0", INT2FIX( HTP_SERVER_IIS_4_0 ) );
  rb_define_const( mHTP, "HTP_SERVER_IIS_5_0", INT2FIX( HTP_SERVER_IIS_5_0 ) );
  rb_define_const( mHTP, "HTP_SERVER_IIS_5_1", INT2FIX( HTP_SERVER_IIS_5_1 ) );
  rb_define_const( mHTP, "HTP_SERVER_IIS_6_0", INT2FIX( HTP_SERVER_IIS_6_0 ) );
  rb_define_const( mHTP, "HTP_SERVER_IIS_7_0", INT2FIX( HTP_SERVER_IIS_7_0 ) );
  rb_define_const( mHTP, "HTP_SERVER_IIS_7_5", INT2FIX( HTP_SERVER_IIS_7_5 ) );
  rb_define_const( mHTP, "HTP_SERVER_TOMCAT_6_0", INT2FIX( HTP_SERVER_TOMCAT_6_0 ) );
  rb_define_const( mHTP, "HTP_SERVER_APACHE", INT2FIX( HTP_SERVER_APACHE ) );
  rb_define_const( mHTP, "HTP_SERVER_APACHE_2_2", INT2FIX( HTP_SERVER_APACHE_2_2 ) );
  rb_define_const( mHTP, "NONE", INT2FIX( HTP_AUTH_NONE ) );
  rb_define_const( mHTP, "IDENTITY", INT2FIX( HTP_CODING_IDENTITY ) );
  rb_define_const( mHTP, "CHUNKED", INT2FIX( HTP_CODING_CHUNKED ) );
  rb_define_const( mHTP, "TX_PROGRESS_NEW", INT2FIX( HTP_REQUEST_NOT_STARTED ) );
  rb_define_const( mHTP, "TX_PROGRESS_REQ_LINE", INT2FIX( HTP_REQUEST_LINE ) );
  rb_define_const( mHTP, "TX_PROGRESS_REQ_HEADERS", INT2FIX( HTP_REQUEST_HEADERS ) );
  rb_define_const( mHTP, "TX_PROGRESS_REQ_BODY", INT2FIX( HTP_REQUEST_BODY ) );
  rb_define_const( mHTP, "TX_PROGRESS_REQ_TRAILER", INT2FIX( HTP_REQUEST_TRAILER ) );
  rb_define_const( mHTP, "RESPONSE_WAIT", INT2FIX( HTP_REQUEST_COMPLETE ) );
  rb_define_const( mHTP, "TX_PROGRESS_RES_LINE", INT2FIX( HTP_RESPONSE_LINE ) );
  rb_define_const( mHTP, "RESPONSE_HEADERS", INT2FIX( HTP_RESPONSE_HEADERS ) );
  rb_define_const( mHTP, "RESPONSE_BODY", INT2FIX( HTP_RESPONSE_BODY ) );
  rb_define_const( mHTP, "TX_PROGRESS_RES_TRAILER", INT2FIX( HTP_RESPONSE_TRAILER ) );
  rb_define_const( mHTP, "TX_PROGRESS_COMPLETE", INT2FIX( HTP_RESPONSE_COMPLETE ) );
  rb_define_const( mHTP, "HTP_STREAM_NEW", INT2FIX( HTP_STREAM_NEW ) );
  rb_define_const( mHTP, "HTP_STREAM_OPEN", INT2FIX( HTP_STREAM_OPEN ) );
  rb_define_const( mHTP, "HTP_STREAM_CLOSED", INT2FIX( HTP_STREAM_CLOSED ) );
  rb_define_const( mHTP, "HTP_STREAM_ERROR", INT2FIX( HTP_STREAM_ERROR ) );
  rb_define_const( mHTP, "HTP_STREAM_TUNNEL", INT2FIX( HTP_STREAM_TUNNEL ) );
  rb_define_const( mHTP, "HTP_STREAM_DATA_OTHER", INT2FIX( HTP_STREAM_DATA_OTHER ) );
  rb_define_const( mHTP, "HTP_STREAM_DATA", INT2FIX( HTP_STREAM_DATA ) );
  rb_define_const( mHTP, "URL_DECODER_PRESERVE_PERCENT", INT2FIX( HTP_URL_DECODE_PRESERVE_PERCENT ) );
  rb_define_const( mHTP, "URL_DECODER_REMOVE_PERCENT", INT2FIX( HTP_URL_DECODE_REMOVE_PERCENT ) );
  rb_define_const( mHTP, "URL_DECODER_DECODE_INVALID", INT2FIX( HTP_URL_DECODE_PROCESS_INVALID ) );
  rb_define_const( mHTP, "URL_DECODER_STATUS_400", INT2FIX( HTP_URL_DECODE_STATUS_400 ) );
  rb_define_const( mHTP, "NO", INT2FIX( NO ) );
  rb_define_const( mHTP, "BESTFIT", INT2FIX( BESTFIT ) );
  rb_define_const( mHTP, "YES", INT2FIX( YES ) );
  rb_define_const( mHTP, "TERMINATE", INT2FIX( TERMINATE ) );
  rb_define_const( mHTP, "STATUS_400", INT2FIX( STATUS_400 ) );
  rb_define_const( mHTP, "STATUS_404", INT2FIX( STATUS_404 ) );
  rb_define_const( mHTP, "HTP_AUTH_NONE", INT2FIX( HTP_AUTH_NONE ) );
  rb_define_const( mHTP, "HTP_AUTH_BASIC", INT2FIX( HTP_AUTH_BASIC ) );
  rb_define_const( mHTP, "HTP_AUTH_DIGEST", INT2FIX( HTP_AUTH_DIGEST ) );
  rb_define_const( mHTP, "HTP_AUTH_UNKNOWN", INT2FIX( HTP_AUTH_UNRECOGNIZED ) );
  rb_define_const( mHTP, "HTP_FILE_MULTIPART", INT2FIX( HTP_FILE_MULTIPART ) );
  rb_define_const( mHTP, "HTP_FILE_PUT", INT2FIX( HTP_FILE_PUT ) );
  rb_define_const( mHTP, "CFG_NOT_SHARED", INT2FIX( CFG_NOT_SHARED ) );
  rb_define_const( mHTP, "CFG_SHARED", INT2FIX( CFG_SHARED ) );

	cCfg = rb_define_class_under( mHTP, "Cfg", rb_cObject );
	rb_define_method( cCfg, "initialize", rbhtp_config_initialize, 0 );
	rb_define_method( cCfg, "copy", rbhtp_config_copy, 0 );

	rb_define_method( cCfg, "register_response", rbhtp_config_register_response, 0 );
	rb_define_method( cCfg, "register_request", rbhtp_config_register_request, 0 );
	rb_define_method( cCfg, "register_transaction_start", rbhtp_config_register_transaction_start, 0 );
	rb_define_method( cCfg, "register_request_line", rbhtp_config_register_request_line, 0 );
	rb_define_method( cCfg, "register_request_headers", rbhtp_config_register_request_headers, 0 );
	rb_define_method( cCfg, "register_request_trailer", rbhtp_config_register_request_trailer, 0 );
	rb_define_method( cCfg, "register_response_line", rbhtp_config_register_response_line, 0 );
	rb_define_method( cCfg, "register_response_headers", rbhtp_config_register_response_headers, 0 );
	rb_define_method( cCfg, "register_response_trailer", rbhtp_config_register_response_trailer, 0 );
	
	rb_define_method( cCfg, "register_urlencoded_parser", rbhtp_config_register_urlencoded_parser, 0 );
	rb_define_method( cCfg, "register_request_body_data", rbhtp_config_register_request_body_data, 0 );
	rb_define_method( cCfg, "register_response_body_data", rbhtp_config_register_request_body_data, 0 );
	rb_define_method( cCfg, "register_request_file_data", rbhtp_config_register_request_file_data, 0 );
	
	// server_personality= and server_personality are defined in htp_ruby.rb	
	rb_define_method( cCfg, "set_server_personality", rbhtp_config_set_server_personality, 1 );
	rb_define_method( cCfg, "spersonality", rbhtp_cfg_spersonality, 0 );
	
	rb_define_method( cCfg, "parse_request_cookies", rbhtp_cfg_parse_request_cookies, 0 );
	rb_define_method( cCfg, "parse_request_cookies=", rbhtp_cfg_parse_request_cookies_set, 1 );
	// TODO: Much more to add.
		
	cConnp = rb_define_class_under( mHTP, "Connp", rb_cObject );
	rb_define_method( cConnp, "initialize", rbhtp_connp_initialize, 1 );
	rb_define_method( cConnp, "req_data", rbhtp_connp_req_data, 2 );	
	rb_define_method( cConnp, "in_tx", rbhtp_connp_in_tx, 0 );	
	rb_define_method( cConnp, "conn", rbhtp_connp_conn, 0 );
	// TODO: Much more to Add.
	
	cHeader = rb_define_class_under( mHTP, "Header", rb_cObject );
	rb_define_method( cHeader, "initialize", rbhtp_header_initialize, 1 );
	rb_define_method( cHeader, "name", rbhtp_header_name, 0 );
	rb_define_method( cHeader, "value", rbhtp_header_value, 0 );
	rb_define_method( cHeader, "flags", rbhtp_header_flags, 0 );
	
	cHeaderLine = rb_define_class_under( mHTP, "HeaderLine", rb_cObject );
	rb_define_method( cHeaderLine, "initialize", rbhtp_header_line_initialize, 1 );
	rb_define_method( cHeaderLine, "header", rbhtp_header_line_header, 0 );
	rb_define_method( cHeaderLine, "line", rbhtp_header_line_line, 0 );
	rb_define_method( cHeaderLine, "name_offset", rbhtp_header_line_name_offset, 0 );
	rb_define_method( cHeaderLine, "name_len", rbhtp_header_line_name_len, 0 );
	rb_define_method( cHeaderLine, "value_offset", rbhtp_header_line_value_offset, 0 );
	rb_define_method( cHeaderLine, "value_len", rbhtp_header_line_value_len, 0 );
	rb_define_method( cHeaderLine, "has_nulls", rbhtp_header_line_has_nulls, 0 );
	rb_define_method( cHeaderLine, "first_nul_offset", rbhtp_header_line_first_nul_offset, 0 );
	rb_define_method( cHeaderLine, "flags", rbhtp_header_line_flags, 0 );
	
	cURI = rb_define_class_under( mHTP, "URI", rb_cObject );
	rb_define_method( cURI, "initialize", rbhtp_uri_initialize, 1 );
	
	rb_define_method( cURI, "scheme", rbhtp_uri_scheme, 0 );
	rb_define_method( cURI, "username", rbhtp_uri_username, 0 );
	rb_define_method( cURI, "password", rbhtp_uri_password, 0 );
	rb_define_method( cURI, "hostname", rbhtp_uri_hostname, 0 );
	rb_define_method( cURI, "port", rbhtp_uri_port, 0 );
	rb_define_method( cURI, "port_number", rbhtp_uri_port_number, 0 );
	rb_define_method( cURI, "path", rbhtp_uri_path, 0 );
	rb_define_method( cURI, "query", rbhtp_uri_query, 0 );
	rb_define_method( cURI, "fragment", rbhtp_uri_fragment, 0 );
	
	cTx = rb_define_class_under( mHTP, "Tx", rb_cObject );
	rb_define_method( cTx, "initialize", rbhtp_tx_initialize, 3 );

	rb_define_method( cTx, "request_ignored_lines", rbhtp_tx_request_ignored_lines, 0 );
	rb_define_method( cTx, "request_line_nul", rbhtp_tx_request_line_nul, 0 );
	rb_define_method( cTx, "request_line_nul_offset", rbhtp_tx_request_line_nul_offset, 0 );
	rb_define_method( cTx, "request_method_number", rbhtp_tx_request_method_number, 0 );
	rb_define_method( cTx, "request_line", rbhtp_tx_request_line, 0 );
	rb_define_method( cTx, "request_method", rbhtp_tx_request_method, 0 );	
	rb_define_method( cTx, "request_uri", rbhtp_tx_request_uri, 0 );
	rb_define_method( cTx, "request_uri_normalized", rbhtp_tx_request_uri_normalized, 0 );
  rb_define_method( cTx, "request_protocol", rbhtp_tx_request_protocol, 0 );
  rb_define_method( cTx, "request_headers_raw", rbhtp_tx_request_headers_raw, 0 );
  rb_define_method( cTx, "request_headers_sep", rbhtp_tx_request_headers_sep, 0 );
  rb_define_method( cTx, "request_content_type", rbhtp_tx_request_content_type, 0 );
  rb_define_method( cTx, "request_auth_username", rbhtp_tx_request_auth_username, 0 );
  rb_define_method( cTx, "request_auth_password", rbhtp_tx_request_auth_password, 0 );
  rb_define_method( cTx, "response_line", rbhtp_tx_response_line, 0 );
  rb_define_method( cTx, "response_protocol", rbhtp_tx_response_protocol, 0 );
  rb_define_method( cTx, "response_status", rbhtp_tx_response_status, 0 );
  rb_define_method( cTx, "response_message", rbhtp_tx_response_message, 0 );
  rb_define_method( cTx, "response_headers_sep", rbhtp_tx_response_headers_sep, 0 );
  rb_define_method( cTx, "request_protocol_number", rbhtp_tx_request_protocol_number, 0 );
  rb_define_method( cTx, "protocol_is_simple", rbhtp_tx_protocol_is_simple, 0 );
  rb_define_method( cTx, "request_message_len", rbhtp_tx_request_message_len, 0 );
  rb_define_method( cTx, "request_entity_len", rbhtp_tx_request_entity_len, 0 );
  rb_define_method( cTx, "request_nonfiledata_len", rbhtp_tx_request_nonfiledata_len, 0 );
  rb_define_method( cTx, "request_filedata_len", rbhtp_tx_request_filedata_len, 0 );
  rb_define_method( cTx, "request_header_lines_no_trailers", rbhtp_tx_request_header_lines_no_trailers, 0 );
  rb_define_method( cTx, "request_headers_raw_lines", rbhtp_tx_request_headers_raw_lines, 0 );
  rb_define_method( cTx, "request_transfer_coding", rbhtp_tx_request_transfer_coding, 0 );
  rb_define_method( cTx, "request_content_encoding", rbhtp_tx_request_content_encoding, 0 );
  rb_define_method( cTx, "request_params_query_reused", rbhtp_tx_request_params_query_reused, 0 );
  rb_define_method( cTx, "request_params_body_reused", rbhtp_tx_request_params_body_reused, 0 );
  rb_define_method( cTx, "request_auth_type", rbhtp_tx_request_auth_type, 0 );
  rb_define_method( cTx, "response_ignored_lines", rbhtp_tx_response_ignored_lines, 0 );
  rb_define_method( cTx, "response_protocol_number", rbhtp_tx_response_protocol_number, 0 );
  rb_define_method( cTx, "response_status_number", rbhtp_tx_response_status_number, 0 );
  rb_define_method( cTx, "response_status_expected_number", rbhtp_tx_response_status_expected_number, 0 );
  rb_define_method( cTx, "seen_100continue", rbhtp_tx_seen_100continue, 0 );
  rb_define_method( cTx, "response_message_len", rbhtp_tx_response_message_len, 0 );
  rb_define_method( cTx, "response_entity_len", rbhtp_tx_response_entity_len, 0 );
  rb_define_method( cTx, "response_transfer_coding", rbhtp_tx_response_transfer_coding, 0 );
  rb_define_method( cTx, "response_content_encoding", rbhtp_tx_response_content_encoding, 0 );
  rb_define_method( cTx, "flags", rbhtp_tx_flags, 0 );
  rb_define_method( cTx, "progress", rbhtp_tx_progress, 0 );

	rb_define_method( cTx, "request_params_query", rbhtp_tx_request_params_query, 0 );
	rb_define_method( cTx, "request_params_body", rbhtp_tx_request_params_body, 0 );
	rb_define_method( cTx, "request_cookies", rbhtp_tx_request_cookies, 0 );
	rb_define_method( cTx, "request_headers", rbhtp_tx_request_headers, 0 );
	rb_define_method( cTx, "response_headers", rbhtp_tx_response_headers, 0 );
	
	rb_define_method( cTx, "request_header_lines", rbhtp_tx_request_header_lines, 0 );
	rb_define_method( cTx, "response_header_lines", rbhtp_tx_response_header_lines, 0 );
	
	rb_define_method( cTx, "parsed_uri", rbhtp_tx_parsed_uri, 0 );
	rb_define_method( cTx, "parsed_uri_incomplete", rbhtp_tx_parsed_uri_incomplete, 0 );
	
	rb_define_method( cTx, "conn", rbhtp_tx_conn, 0 );
	
	cFile = rb_define_class_under( mHTP, "File", rb_cObject );
	rb_define_method( cFile, "initialize", rbhtp_file_initialize, 1 );
	
	rb_define_method( cFile, "source", rbhtp_file_source, 0 );
	rb_define_method( cFile, "filename", rbhtp_file_filename, 0 );
	rb_define_method( cFile, "len", rbhtp_file_len, 0 );
	rb_define_method( cFile, "tmpname", rbhtp_file_tmpname, 0 );
	rb_define_method( cFile, "fd", rbhtp_file_fd, 0 );
	
	cConn = rb_define_class_under( mHTP, "Conn", rb_cObject );
	rb_define_method( cConn, "initialize", rbhtp_conn_initialize, 2 );
	
	rb_define_method( cConn, "remote_addr", rbhtp_conn_remote_addr, 0 );
	rb_define_method( cConn, "remote_port", rbhtp_conn_remote_port, 0 );
	rb_define_method( cConn, "local_addr", rbhtp_conn_local_addr, 0 );
	rb_define_method( cConn, "local_port", rbhtp_conn_local_port, 0 );
	rb_define_method( cConn, "flags", rbhtp_conn_flags, 0 );
	rb_define_method( cConn, "in_data_counter", rbhtp_conn_in_data_counter, 0 );
	rb_define_method( cConn, "out_data_counter", rbhtp_conn_out_data_counter, 0 );
	rb_define_method( cConn, "in_packet_counter", rbhtp_conn_in_packet_counter, 0 );
	rb_define_method( cConn, "out_packet_counter", rbhtp_conn_out_packet_counter, 0 );
	rb_define_method( cConn, "transactions", rbhtp_conn_transactions, 0 );
	rb_define_method( cConn, "open_timestamp", rbhtp_conn_open_timestamp, 0 );
	rb_define_method( cConn, "close_timestamp", rbhtp_conn_close_timestamp, 0 );
	
	// Load ruby code.
	rb_require( "htp_ruby" );
}
