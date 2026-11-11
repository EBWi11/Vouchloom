# wolfCrypt-OpenSSL HMAC routing

The public `wolfCrypt-OpenSSL` module constructs a fresh Datasource from an
HMAC execution's modifier. Its first `Get<bool>()` selects the implementation
family. An absent value defaults to `true`. In the ordinary non-BoringSSL,
non-OpenSSL-1.0.2 build:

- `true` selects the EVP_PKEY / EVP_DigestSign helper.
- `false` selects the direct HMAC_CTX helper, whose public call sequence is
  reset, Init_ex, Update, Final, and context cleanup.

Encode that selector structurally:

```json
{
  "module": "wolfCrypt-OpenSSL",
  "modifier_fields": [{"type": "bool", "value": false}]
}
```

Bind the build macros before transferring this mapping to BoringSSL or
OpenSSL-1.0.2 variants. Any later modifier fields belong to the selected helper
and must be derived from that version's public module source.
