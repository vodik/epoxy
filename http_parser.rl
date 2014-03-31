#include "http_parser.h"

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#include "util.h"

#define LEN(AT, FPC) (FPC - sock->buf - parser->AT)
#define MARK(M,FPC) (parser->M = (FPC) - sock->buf)
#define PTR_TO(F) (sock->buf + parser->F)

/** Machine **/
%%{
    machine http_parser;

    action mark { MARK(mark, fpc); }

    action start_field { MARK(field_start, fpc); }
    action write_field {
        parser->field_len = LEN(field_start, fpc);
    }

    action start_value { MARK(mark, fpc); }
    action write_value {
        if(cbs->http_field != NULL)
            cbs->http_field(cbs->data, PTR_TO(field_start), parser->field_len, PTR_TO(mark), LEN(mark, fpc));
    }

    action request_method {
        if(cbs->request_method != NULL)
            cbs->request_method(cbs->data, PTR_TO(mark), LEN(mark, fpc));
    }

    action request_uri {
        if(cbs->request_uri != NULL)
            cbs->request_uri(cbs->data, PTR_TO(mark), LEN(mark, fpc));
    }

    action fragment {
        if(cbs->fragment != NULL)
            cbs->fragment(cbs->data, PTR_TO(mark), LEN(mark, fpc));
    }

    action start_query {MARK(query_start, fpc); }
    action query_string {
        if(cbs->query_string != NULL)
            cbs->query_string(cbs->data, PTR_TO(query_start), LEN(query_start, fpc));
    }

    action http_version {
        if(cbs->http_version != NULL)
            cbs->http_version(cbs->data, PTR_TO(mark), LEN(mark, fpc));
    }

    action request_path {
        if(cbs->request_path != NULL)
            cbs->request_path(cbs->data, PTR_TO(mark), LEN(mark,fpc));
    }

    action done {
        parser->body_start = fpc - sock->buf + 1;

        if(cbs->header_done != NULL)
            cbs->header_done(cbs->data, fpc + 1, sock->pe - fpc - 1);
        fbreak;
    }

#### HTTP PROTOCOL GRAMMAR
    CRLF = ( "\r\n" | "\n" );

    # URI description as per RFC 3986
    sub_delims  = ( "!" | "$" | "&" | "'" | "(" | ")" | "*"
                  | "+" | "," | ";" | "=" );
    gen_delims  = ( ":" | "/" | "?" | "#" | "[" | "]" | "@" );
    reserved    = ( gen_delims | sub_delims );
    unreserved  = ( alpha | digit | "-" | "." | "_" | "~" );
    pct_encoded = ( "%" xdigit xdigit );
    pchar       = ( unreserved | pct_encoded | sub_delims | ":" | "@" );
    fragment    = ( ( pchar | "/" | "?" )* ) >mark %fragment;
    query       = ( ( pchar | "/" | "?" )* ) %query_string;

     # non_zero_length segment without any colon ":" ) ;
    segment_nz_nc = ( ( unreserved | pct_encoded | sub_delims | "@" )+ );
    segment_nz    = ( pchar+ );
    segment       = ( pchar* );

    path_empty    = ( null );
    path_rootless = ( segment_nz ( "/" segment )* );
    path_noscheme = ( segment_nz_nc ( "/" segment )* );
    path_absolute = ( "/" ( segment_nz ( "/" segment )* )? );
    path_abempty  = ( ( "/" segment )* );

    path = ( path_abempty  # begins with "/" or is empty
           | path_absolute # begins with "/" but not "//"
           | path_noscheme # begins with a non-colon segment
           | path_rootless # begins with a segment
           | path_empty    # zero characters
           );

    reg_name = ( unreserved | pct_encoded | sub_delims )*;

    dec_octet = ( digit               # 0-9
                | ("1"-"9") digit     # 10-99
                | "1" digit{2}        # 100-199
                | "2" ("0"-"4") digit # 200-249
                | "25" ("0"-"5")      # 250-255
                );

    IPv4address = ( dec_octet "." dec_octet "." dec_octet "." dec_octet );
    h16 = ( xdigit{1,4} );
    ls32 = ( ( h16 ":" h16 ) | IPv4address );

    IPv6address = (                               6( h16 ":" ) ls32
                  |                          "::" 5( h16 ":" ) ls32
                  | (                 h16 )? "::" 4( h16 ":" ) ls32
                  | ( ( h16 ":" ){1,} h16 )? "::" 3( h16 ":" ) ls32
                  | ( ( h16 ":" ){2,} h16 )? "::" 2( h16 ":" ) ls32
                  | ( ( h16 ":" ){3,} h16 )? "::"    h16 ":"   ls32
                  | ( ( h16 ":" ){4,} h16 )? "::"              ls32
                  | ( ( h16 ":" ){5,} h16 )? "::"    h16
                  | ( ( h16 ":" ){6,} h16 )? "::"
                  );

    IPvFuture = ( "v" xdigit+ "." ( unreserved | sub_delims | ":" )+ );

    IP_literal = ( "[" ( IPv6address | IPvFuture ) "]" ) ;

    port      = ( digit* );
    host      = ( IP_literal | IPv4address | reg_name );
    userinfo  = ( ( unreserved | pct_encoded | sub_delims | ":" )* );
    authority = ( ( userinfo "@" )? host ( ":" port )? );

    scheme = ( alpha ( alpha | digit | "+" | "-" | "." )* );

    relative_part = ( "//" authority path_abempty
                    | path_absolute
                    | path_noscheme
                    | path_empty
                    );


    hier_part = ( "//" authority path_abempty
                | path_absolute
                | path_rootless
                | path_empty
                );

    absolute_URI = ( scheme ":" hier_part ( "?" query )? );

    relative_ref = ( (relative_part %request_path ( "?" %start_query query )?) >mark %request_uri ( "#" fragment )? );
    URI = ( scheme ":" (hier_part %request_path ( "?" %start_query query )?) >mark %request_uri ( "#" fragment )? );

    URI_reference = ( URI | relative_ref );

    # HTTP header parsing
    Method = ( upper | digit ){1,20} >mark %request_method;

    http_number = ( "1." ("0" | "1") );
    HTTP_Version = ( "HTTP/" http_number ) >mark %http_version;
    Request_Line = ( Method " " URI_reference " " HTTP_Version CRLF );

    HTTP_CTL       = (0 - 31) | 127;
    HTTP_separator = ( "(" | ")" | "<" | ">" | "@"
                     | "," | ";" | ":" | "\\" | "\""
                     | "/" | "[" | "]" | "?" | "="
                     | "{" | "}" | " " | "\t"
                     );

    lws     = CRLF? (" " | "\t")+;
    token   = ascii -- ( HTTP_CTL | HTTP_separator );
    content = ((any -- HTTP_CTL) | lws);

    field_name  = ( token )+ >start_field %write_field;
    field_value = content* >start_value %write_value;

    message_header = field_name ":" lws* field_value :> CRLF;

    Request = Request_Line ( message_header )* ( CRLF );

    main := Request @done;
}%%

/** Data **/
%% write data;

void http_parser_init(struct http_parser *parser, struct sock *sock)
{
    %%access sock->;
    %%variable p sock->p;
    %%variable pe sock->pe;
    %%write init;

    zero(parser, sizeof(struct http_parser));
}

/** exec **/
size_t http_parser_execute(struct http_parser *parser, struct sock *sock, struct http_callbacks *cbs)
{
    if (sock->len == 0)
        return 0;

    /* const char *p, *pe; */
    /* int cs = parser->cs; */

    /* p = sock->buf; */
    /* pe = sock->buf + len; */

    %%access sock->;
    %%variable p sock->p;
    %%variable pe sock->pe;
    %%write exec;

    assert(sock->p <= sock->pe && "Buffer overflow after parsing.");

    /* if (!http_parser_has_error(parser)) { */
    /*     sock->cs = cs; */
    /* } */

    parser->nread += sock->p - sock->buf;

    assert(parser->nread <= sock->len && "nread longer than length");
    assert(parser->body_start <= sock->len && "body starts after sock->buf end");
    assert(parser->mark < sock->len && "mark is after sock->buf end");
    assert(parser->field_len <= sock->len && "field has length longer than whole sock->buf");
    assert(parser->field_start < sock->len && "field starts after sock->buf end");

    return parser->nread;
}

int http_parser_finish(struct sock *sock)
{
    if (http_parser_has_error(sock)) {
        return -1;
    } else if (http_parser_is_finished(sock) ) {
        return 1;
    } else {
        return 0;
    }
}

int http_parser_has_error(struct sock *sock)
{
    return sock->cs == http_parser_error;
}

int http_parser_is_finished(struct sock *sock)
{
    return sock->cs >= http_parser_first_final;
}
