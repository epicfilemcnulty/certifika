### Let's Encrypt Directory endpoints
LE stage url:
* stage: https://acme-staging-v02.api.letsencrypt.org/directory
* prod: https://acme-v02.api.letsencrypt.org/directory

### RFC 8555 extracts

Also see https://github.com/letsencrypt/boulder/blob/master/docs/acme-divergences.md

```
ACME clients MUST send a User-Agent header field, in accordance with
[RFC7231]. This header field SHOULD include the name and version of
the ACME software in addition to the name and version of the
underlying HTTP client software.

ACME clients SHOULD send an Accept-Language header field in
accordance with [RFC7231] to enable localization of error messages.

Binary fields in the JSON objects used by ACME are encoded using
base64url encoding described in Section 5 of [RFC4648] according to
the profile specified in JSON Web Signature in Section 2 of
[RFC7515]. This encoding uses a URL safe character set. Trailing
'=' characters MUST be stripped. Encoded values that include
trailing '=' characters MUST be rejected as improperly encoded.

Because client requests in ACME carry JWS objects in the Flattened
JSON Serialization, they must have the Content-Type header field set
to "application/jose+json". If a request does not meet this
requirement, then the server MUST return a response with status code
415 (Unsupported Media Type).
```

### Example requests

```
HEAD /acme/new-nonce HTTP/1.1
Host: example.com
HTTP/1.1 200 OK
Replay-Nonce: oFvnlFP1wIhRlYS2jTaXbA
Cache-Control: no-store
Link: <https://example.com/acme/directory>;rel="index"
```

```
POST /acme/new-account HTTP/1.1
Host: example.com
Content-Type: application/jose+json

{
    "protected": base64url({
        "alg": "ES256",
        "jwk": {...},
        "nonce": "6S8IqOGY7eL2lsGoTZYifg",
        "url": "https://example.com/acme/new-account"
    }),
    "payload": base64url({
        "termsOfServiceAgreed": true,
        "contact": [
            "mailto:cert-admin@example.org",
            "mailto:admin@example.org"
        ]
    }),
    "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
}
```
