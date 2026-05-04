when defined(macosx):
  {.passL:"-L/opt/local/lib -lopendmarc".}
  {.passC:"-I/usr/local/include".}
elif defined(linux):
  {.passL:"-L/usr/lib/x86_64-linux-gnu -lopendmarc".}
  {.passC:"-I/usr/include".}

import unittest
import ../src/opendmarc

suite "opendmarc low-level bindings":
  test "status strings are available for known status codes":
    let known = [
      DMARC_PARSE_OKAY,
      DMARC_PARSE_ERROR_EMPTY,
      DMARC_PARSE_ERROR_BAD_VERSION,
      DMARC_POLICY_NONE,
      DMARC_POLICY_REJECT
    ]

    for st in known:
      let txt = opendmarc_policy_status_to_str(st.cint)
      check txt != nil
      check ($txt).len > 0

  test "library init/shutdown succeeds":
    var lib = OPENDMARC_LIB_T()
    let rcInit = opendmarc_policy_library_init(lib.addr)
    check rcInit == DMARC_PARSE_OKAY

    let rcShutdown = opendmarc_policy_library_shutdown(lib.addr)
    check rcShutdown == DMARC_PARSE_OKAY

  test "connection context lifecycle works":
    var ip4: array[4, uint8] = [127'u8, 0'u8, 0'u8, 1'u8]

    let ctx = opendmarc_policy_connect_init(
      cast[ptr uint8](ip4[0].addr),
      DMARC_POLICY_IP_TYPE_IPV4.cint
    )
    check ctx != nil

    discard opendmarc_policy_connect_rset(ctx)
    discard opendmarc_policy_connect_shutdown(ctx)

  test "parse a DMARC record and fetch parsed fields":
    var ip4: array[4, uint8] = [127'u8, 0'u8, 0'u8, 1'u8]
    let ctx = opendmarc_policy_connect_init(
      cast[ptr uint8](ip4[0].addr),
      DMARC_POLICY_IP_TYPE_IPV4.cint
    )
    check ctx != nil

    let domain = "example.com".cstring
    let record = "v=DMARC1; p=none; adkim=s; aspf=r; pct=100".cstring

    let rcParse = opendmarc_policy_parse_dmarc(
      ctx,
      cast[ptr uint8](domain),
      cast[ptr uint8](record)
    )
    check rcParse == DMARC_PARSE_OKAY

    var pct, adkim, aspf, p: cint

    check opendmarc_policy_fetch_pct(ctx, pct.addr) == DMARC_PARSE_OKAY
    check opendmarc_policy_fetch_adkim(ctx, adkim.addr) == DMARC_PARSE_OKAY
    check opendmarc_policy_fetch_aspf(ctx, aspf.addr) == DMARC_PARSE_OKAY
    check opendmarc_policy_fetch_p(ctx, p.addr) == DMARC_PARSE_OKAY

    check pct >= 0 and pct <= 100

    let enforced = opendmarc_get_policy_to_enforce(ctx)
    check(
      enforced == DMARC_POLICY_NONE or
      enforced == DMARC_POLICY_QUARANTINE or
      enforced == DMARC_POLICY_REJECT or
      enforced == DMARC_POLICY_ABSENT
    )

    var outBuf = newString(512)
    let rcBuf = opendmarc_policy_to_buf(ctx, outBuf.cstring, outBuf.len.csize_t)
    check rcBuf >= 0

    discard opendmarc_policy_connect_shutdown(ctx)