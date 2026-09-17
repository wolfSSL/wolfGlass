# wolfSSL Release 5.9.1 (Apr. 8, 2026)

Release 5.9.1 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE:
* --enable-heapmath is deprecated
* MD5 is now disabled by default

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request number where the code change was added.

## Vulnerabilities

* [Critical] CVE-2026-5194
Missing hash/digest size and OID checks allow digests smaller than allowed by FIPS 186-4 or 186-5 (as appropriate), or smaller than is appropriate for the relevant key type, to be accepted by signature verification functions, reducing the security of certificate-based authentication. Affects multiple signature algorithms, including ECDSA/ECC, DSA, ML-DSA, ED25519, and ED448. Builds that have both ECC and EdDSA or ML-DSA enabled that are doing certificate verification are recommended to update to the latest wolfSSL release. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10131.

* [High] CVE-2026-5264
Heap buffer overflow in DTLS 1.3 ACK message processing. A remote attacker can send a crafted DTLS 1.3 ACK message that triggers a heap buffer overflow. Thanks to Sunwoo Lee and Seunghyun Yoon, Korea Institute of Energy Technology (KENTECH). Fixed in PR 10076.

* [High] CVE-2026-5263
URI nameConstraints from constrained intermediate CAs are parsed but not enforced during certificate chain verification in wolfcrypt/src/asn.c. A compromised or malicious sub-CA could issue leaf certificates with URI SAN entries that violate the nameConstraints of the issuing CA, and wolfSSL would accept them as valid. Thanks to Oleh Konko @1seal for the report. Fixed in PR 10048.

* [High] CVE-2026-5295
Stack buffer overflow in PKCS7 ORI (Other Recipient Info) OID processing. When parsing a PKCS7 envelope with a crafted ORI OID value, a stack-based buffer overflow can be triggered. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH). Fixed in PR 10116.

* [High] CVE-2026-5466
wolfSSL's ECCSI signature verifier `wc_VerifyEccsiHash` decodes the `r` and `s` scalars from the signature blob via `mp_read_unsigned_bin` with no check that they lie in `[1, q-1]`. A crafted forged signature could verify against any message for any identity, using only publicly-known constants. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5477
Potential for AES-EAX AEAD and CMAC authentication bypass on messages larger than 4 GiB. An attacker who observes one valid (ciphertext, tag) pair for a >4 GiB EAX message can replace the first 4 GiB of ciphertext arbitrarily while the tag still verifies. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5447
Heap buffer overflow in CertFromX509 via AuthorityKeyIdentifier size confusion. A heap buffer overflow occurs when converting an X.509 certificate internally due to incorrect size handling of the AuthorityKeyIdentifier extension. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10112.

* [High] CVE-2026-5500
wolfSSL's `wc_PKCS7_DecodeAuthEnvelopedData()` does not properly sanitize the AES-GCM authentication tag length received and has no lower bounds check. A man-in-the-middle can therefore truncate the `mac` field from 16 bytes to 1 byte, reducing the tag check from 2⁻¹²⁸ to 2⁻⁸. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5501
`wolfSSL_X509_verify_cert()` in the OpenSSL compatibility layer accepts a certificate chain in which the leaf's signature is not checked, if the attacker supplies an untrusted intermediate with Basic Constraints `CA:FALSE` that is legitimately signed by a trusted root. An attacker who obtains any leaf certificate from a trusted CA (e.g. a free DV cert from Let's Encrypt) can forge a certificate for any subject name with any public key and arbitrary signature bytes, and the function returns `WOLFSSL_SUCCESS` / `X509_V_OK`. The native wolfSSL TLS handshake path (`ProcessPeerCerts`) is not susceptible and the issue is limited to applications using the OpenSSL compatibility API directly. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5503
In TLSX_EchChangeSNI, the ctx->extensions branch set extensions unconditionally even when TLSX_Find returned NULL. This caused TLSX_UseSNI to attach the attacker-controlled publicName to the shared WOLFSSL_CTX when no inner SNI was configured. TLSX_EchRestoreSNI then failed to clean it up because its removal was gated on serverNameX != NULL. The inner ClientHello was sized before the pollution but written after it, causing TLSX_SNI_Write to memcpy 255 bytes past the allocation boundary. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [High] CVE-2026-5479
In wolfSSL's EVP layer, the ChaCha20-Poly1305 AEAD decryption path in wolfSSL_EVP_CipherFinal (and related EVP cipher finalization functions) fails to verify the authentication tag before returning plaintext to the caller. When an application uses the EVP API to perform ChaCha20-Poly1305 decryption, the implementation computes or accepts the tag but does not compare it against the expected value. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10102.

* [Med] CVE-2026-5392
Heap out-of-bounds read in PKCS7 parsing. A crafted PKCS7 message can trigger an OOB read on the heap. The missing bounds check is in the indefinite-length end-of-content verification loop in PKCS7_VerifySignedData(). This only affects builds with PKCS7 support enabled. Thanks to J Laratro (d0sf3t) for the report. Fixed in PR 10039.

* [Med] CVE-2026-5446
ARIA-GCM nonce reuse in TLS 1.2 record encryption. ARIA cipher support requires a proprietary Korean library (MagicCrypto) and --enable-aria, limiting real-world exposure. Thanks to Calif.io in collaboration with Claude and Anthropic Research for the report. Fixed in PR 10111.

* [Med] CVE-2026-5460
When a malicious TLS 1.3 server sends a ServerHello with a truncated PQC hybrid KeyShare (e.g., P256_ML_KEM_512 with 10 bytes instead of the required 768+), the error cleanup path double-frees the KyberKey. Thanks to Calvin Young (eWalker Consulting Inc.) and Enoch Chow (Isomorph Cyber). Fixed in PR 10092.

* [Med] CVE-2026-5504
A padding oracle exists in wolfSSL's PKCS7 CBC decryption that could allow an attacker to recover plaintext through repeated decryption queries with modified ciphertext. In previous versions of wolfSSL the interior padding bytes are not validated. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon of Korea Institute of Energy Technology (KENTECH) for the report. Fixed in PR 10088.

* [Med] CVE-2026-5507
When restoring a session from cache, a pointer from the serialized session data is used in a free operation without validation. An attacker who can poison the session cache could trigger an arbitrary free. Exploitation requires the ability to inject a crafted session into the cache and for the application to call specific session restore APIs. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon of Korea Institute of Energy Technology (KENTECH) for the report. Fixed in PR 10088.

* [Low] CVE-2026-5187
Heap out-of-bounds write in DecodeObjectId() caused by an off-by-one bounds check combined with a sizeof mismatch. A crafted ASN.1 object identifier can trigger a small heap OOB write. Thanks to Yuteng for the report. Fixed in PR 10025.

* [Low] CVE-2026-5188
An integer underflow issue exists in wolfSSL when parsing the Subject Alternative Name (SAN) extension of X.509 certificates. A malformed certificate can specify an entry length larger than the enclosing sequence, causing the internal length counter to wrap during parsing. This results in incorrect handling of certificate data. The issue is limited to configurations using the original ASN.1 parsing implementation. The original ASN.1 parsing implementation is off by default. Thanks to Muhammad Arya Arjuna Habibullah for the report. Fixed in PR 10024.

* [Low] CVE-2026-5448
X.509 date buffer overflow in wolfSSL_X509_notAfter / wolfSSL_X509_notBefore. A buffer overflow may occur when parsing date fields from a crafted X.509 certificate via the compatibility layer API. This is only triggered when calling these two APIs directly from an application, and does not affect TLS or certificate verify operations in wolfSSL. Thanks to Sunwoo Lee and Seunghyun Yoon, Korea Institute of Energy Technology (KENTECH) for the report. Fixed in PR 10071.

* [Low] CVE-2026-5772
A 1-byte stack buffer over-read exists in the MatchDomainName function in src/internal.c when processing wildcard patterns with the LEFT_MOST_WILDCARD_ONLY flag active. When a wildcard '*' exhausts the entire hostname string (strLen reaches 0), the function proceeds to compare remaining pattern characters against the now-exhausted buffer without a bounds check, causing an out-of-bounds read. Thanks to Zou Dikai for the report. Fixed in PR 10119.

* [Low] CVE-2026-5778
An integer underflow exists in the ChaCha20-Poly1305 decryption path where a malformed TLS 1.2 record with a payload shorter than the AEAD MAC size causes the message length calculation to underflow, resulting in an out-of-bounds read. This only affects sniffer builds. Thanks to Zou Dikai for the report. Fixed in PR 10125.

## Experimental Build Vulnerability

* [Med] CVE-2026-5393
Dual-Algorithm CertificateVerify out-of-bounds read. When processing a dual-algorithm CertificateVerify message, an out-of-bounds read can occur on crafted input. This can only occur when --enable-experimental and --enable-dual-alg-certs is used when building wolfSSL. Thanks to Sunwoo Lee, Woohyun Choi, and Seunghyun Yoon (Korea Institute of Energy Technology, KENTECH) for testing the fix. Fixed in PR 10079.
