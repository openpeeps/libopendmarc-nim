# OpenDMARC C API bindings for Nim
#
# (c) 2026 George Lemon | MIT license
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/libopendmarc-nim

{.passC: "-include netinet/in.h".}
{.emit: "#include <netinet/in.h>".}
type
  in_addr* {.importc: "struct in_addr", bycopy, header: "<netinet/in.h>".} = object

const
  DMARC_POLICY_IP_TYPE_IPV4* = 4
  DMARC_POLICY_IP_TYPE_IPV6* = 6
  DMARC_PARSE_OKAY* = 0
  DMARC_PARSE_ERROR_EMPTY* = 1
  DMARC_PARSE_ERROR_NULL_CTX* = 2
  DMARC_PARSE_ERROR_BAD_VERSION* = 3
  DMARC_PARSE_ERROR_BAD_VALUE* = 4
  DMARC_PARSE_ERROR_NO_REQUIRED_P* = 5
  DMARC_PARSE_ERROR_NO_DOMAIN* = 6
  DMARC_PARSE_ERROR_NO_ALLOC* = 7
  DMARC_PARSE_ERROR_BAD_SPF_MACRO* = 8
  DMARC_PARSE_ERROR_BAD_DKIM_MACRO = DMARC_PARSE_ERROR_BAD_SPF_MACRO
  DMARC_DNS_ERROR_NO_RECORD* = 9
  DMARC_DNS_ERROR_NXDOMAIN* = 10
  DMARC_DNS_ERROR_TMPERR* = 11
  DMARC_TLD_ERROR_UNKNOWN* = 12
  DMARC_FROM_DOMAIN_ABSENT* = 13

  DMARC_POLICY_ABSENT* = 14
  DMARC_POLICY_PASS* = 15
  DMARC_POLICY_REJECT* = 16
  DMARC_POLICY_QUARANTINE* = 17
  DMARC_POLICY_NONE* = 18

  DMARC_USED_POLICY_IS_P* = 19
  DMARC_USED_POLICY_IS_SP* = 20

{.push importc, header: "opendmarc/dmarc.h".}

type
  DMARC_POLICY_T* {.incompleteStruct.} = object

  OPENDMARC_STATUS_T* = cint

  OPENDMARC_LIB_T* {.bycopy.} = object
    tld_type*: cint
    tld_source_file*: array[2048, uint8]
    nscount*: cint
    nsaddr_list*: array[3, in_addr]

# Function bindings
proc opendmarc_policy_library_init*(lib_init: ptr OPENDMARC_LIB_T): OPENDMARC_STATUS_T
proc opendmarc_policy_library_shutdown*(lib_init: ptr OPENDMARC_LIB_T): OPENDMARC_STATUS_T

proc opendmarc_policy_connect_init*(ip_addr: ptr uint8, ip_type: cint): ptr DMARC_POLICY_T
proc opendmarc_policy_connect_clear*(pctx: ptr DMARC_POLICY_T): ptr DMARC_POLICY_T
proc opendmarc_policy_connect_rset*(pctx: ptr DMARC_POLICY_T): ptr DMARC_POLICY_T
proc opendmarc_policy_connect_shutdown*(pctx: ptr DMARC_POLICY_T): ptr DMARC_POLICY_T

proc opendmarc_policy_store_from_domain*(pctx: ptr DMARC_POLICY_T, domain: ptr uint8): OPENDMARC_STATUS_T
proc opendmarc_policy_store_dkim*(pctx: ptr DMARC_POLICY_T, domain, selector: ptr uint8, result: cint, human_result: ptr uint8): OPENDMARC_STATUS_T
proc opendmarc_policy_store_spf*(pctx: ptr DMARC_POLICY_T, domain: ptr uint8, result, origin: cint, human_result: ptr uint8): OPENDMARC_STATUS_T

proc opendmarc_policy_query_dmarc*(pctx: ptr DMARC_POLICY_T, domain: ptr uint8): OPENDMARC_STATUS_T
proc opendmarc_policy_parse_dmarc*(pctx: ptr DMARC_POLICY_T, domain, record: ptr uint8): OPENDMARC_STATUS_T
proc opendmarc_policy_store_dmarc*(pctx: ptr DMARC_POLICY_T, dmarc_record, domain, organizationaldomain: ptr uint8): OPENDMARC_STATUS_T

proc opendmarc_get_policy_to_enforce*(pctx: ptr DMARC_POLICY_T): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_alignment*(pctx: ptr DMARC_POLICY_T, dkim_alignment, spf_alignment: ptr cint): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_pct*(pctx: ptr DMARC_POLICY_T, pctp: ptr cint): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_adkim*(pctx: ptr DMARC_POLICY_T, adkim: ptr cint): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_aspf*(pctx: ptr DMARC_POLICY_T, aspf: ptr cint): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_p*(pctx: ptr DMARC_POLICY_T, p: ptr cint): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_sp*(pctx: ptr DMARC_POLICY_T, sp: ptr cint): OPENDMARC_STATUS_T

proc opendmarc_policy_fetch_rua*(pctx: ptr DMARC_POLICY_T, list_buf: ptr uint8, size_of_buf: csize_t, constant: cint): ptr ptr uint8
proc opendmarc_policy_fetch_ruf*(pctx: ptr DMARC_POLICY_T, list_buf: ptr uint8, size_of_buf: csize_t, constant: cint): ptr ptr uint8
proc opendmarc_policy_fetch_utilized_domain*(pctx: ptr DMARC_POLICY_T, buf: ptr uint8, buflen: csize_t): OPENDMARC_STATUS_T
proc opendmarc_policy_fetch_from_domain*(pctx: ptr DMARC_POLICY_T, buf: ptr uint8, buflen: csize_t): OPENDMARC_STATUS_T
proc opendmarc_policy_query_dmarc_xdomain*(pctx: ptr DMARC_POLICY_T, uri: ptr uint8): OPENDMARC_STATUS_T
proc opendmarc_get_policy_token_used*(pctx: ptr DMARC_POLICY_T): OPENDMARC_STATUS_T

proc opendmarc_tld_read_file*(path_fname, commentstring, drop, exception: cstring): cint
proc opendmarc_tld_shutdown*(): void

proc opendmarc_xml*(b: cstring, blen: csize_t, e: cstring, elen: csize_t): ptr ptr uint8
proc opendmarc_xml_parse*(fname, err_buf: cstring, err_len: csize_t): ptr ptr uint8

proc opendmarc_dns_fake_record*(name, answer: cstring): void
proc opendmarc_util_clearargv*(ary: ptr ptr uint8): ptr ptr uint8
proc opendmarc_policy_status_to_str*(status: OPENDMARC_STATUS_T): cstring
proc opendmarc_policy_check_alignment*(subdomain, tld: ptr uint8, mode: cint): cint
proc opendmarc_policy_to_buf*(pctx: ptr DMARC_POLICY_T, buf: cstring, buflen: csize_t): cint

proc opendmarc_spf_test*(ip_address, mail_from_domain, helo_domain, spf_record: cstring, soft_fail_as_pass: cint, human_readable: cstring, human_readable_len: csize_t, use_mailfrom: ptr cint): cint
proc opendmarc_spf2_test*(ip_address, mail_from_domain, helo_domain, spf_record: cstring, softfail_okay_flag: cint, human_readable: cstring, human_readable_len: csize_t, used_mfrom: ptr cint): cint

{.pop.}