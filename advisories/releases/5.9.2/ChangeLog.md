# wolfSSL Release 5.9.2 (Jun 23, 2026)

Release 5.9.2 has been developed according to wolfSSL's development and QA
process (see link below) and successfully passed the quality criteria.
https://www.wolfssl.com/about/wolfssl-software-development-process-quality-assurance

NOTE:
* The pre-standardization Dilithium API has been renamed to its FIPS 204 ML-DSA name; the legacy `dilithium.h` header and `wc_dilithium_*` names remain available through a temporary compatibility shim.
* The SLH-DSA Hash sign/verify APIs now require a caller-supplied pre-hashed digest rather than the raw message (see Enhancements below).
* liboqs integrations for ML-KEM, ML-DSA, and SLH-DSA (SPHINCS+) have been removed in favor of the native implementations; the deprecated liblms and libxmss integrations have also been removed.
* **BREAKING (RFC 6960 4.2.2.2)**: OCSP responder authorization is now strictly enforced. Removes the non-compliant `CheckOcspResponderChain()` fallback, which authorized any OCSP responder cert issued by an ancestor of the target's issuer; RFC 6960 4.2.2.2 requires direct issuance by the CA identified in the request. Also removes the now-unused `WOLFSSL_NO_OCSP_ISSUER_CHAIN_CHECK` macro and the `vp` parameter from `CheckOcspResponder()`.

PR stands for Pull Request, and PR <NUMBER> references a GitHub pull request number where the code change was added.

## Vulnerabilities

* [High] CVE-2026-11310
  X.509 trust-chain bypass in the OpenSSL compatibility certificate verifier (wolfSSL_X509_verify_cert()).

  This affects only builds with --enable-opensslextra (OPENSSL_EXTRA) and whose application validates certificates by calling X509_verify_cert() (OpenSSL compatibility layer function) with caller-supplied untrusted intermediate certificates; for those users it is critical, otherwise the library is unaffected.  In particular, native wolfSSL TLS/DTLS usage is not impacted.

  wolfSSL’s X509_verify_cert() temporarily loads each caller-supplied untrusted intermediate into the certificate manager but failed to drop them before the trusted-store check, so an untrusted intermediate could anchor the path itself. An attacker can present a chain that never reaches a configured trust anchor and have it accepted, resulting in acceptance of an attacker-controlled certificate.

  This is certificate verification independent of TLS (e.g. S/MIME/CMS, code/firmware signing, JWT/JWS x5c), is not specific to any key type or algorithm, and a single untrusted intermediate suffices. The default wolfSSL TLS handshake (WOLFSSL_VERIFY_PEER) is not affected; only TLS applications doing manual or deferred peer verification through this API are, which also requires --enable-sessioncerts. Affected: v5.8.4, v5.9.0 and v5.9.1 (introduced by commit 025dbc34); v5.8.2 and earlier are not. Thanks to Corban Villa, Sohee Kim and Austin Chu (UC Berkeley, Sky Lab). Fixed in PR 10674.

* [High] CVE-2026-11999
  X.509 trust-chain bypass (path-depth exhaustion) in the OpenSSL compatibility certificate verifier (wolfSSL_X509_verify_cert()). This affects only builds with --enable-opensslextra whose application calls X509_verify_cert() with caller-supplied untrusted intermediates; for those users it is critical, otherwise the library is unaffected. Native wolfSSL TLS/DTLS usage is not impacted.

  X509_verify_cert() returned success based only on the last verified link rather than on reaching a trust anchor: when the supplied chain is deeper than the verifier's maximum path depth (default 100), path building runs out of depth while still walking untrusted intermediates and the chain is accepted even though it never reaches a configured trust anchor, allowing acceptance of an attacker-controlled certificate. The default TLS handshake (WOLFSSL_VERIFY_PEER) is not affected; only applications doing manual or deferred verification through this API are. Affected versions: v5.7.4 through v5.9.1, introduced in commit 17c9e92b7 (first released in v5.7.4); v5.7.2 and earlier are not affected. Thanks to Corban Villa, Sohee Kim and Austin Chu (UC Berkeley, Sky Lab). Fixed in PR 10674.

* [High] CVE-2026-6679
  A heap buffer overflow could occur in the DTLS 1.3 ACK serialization path before the connecting peer is authenticated. The buffer overflow was due to an integer truncation when computing the length of the ACK record-number list, causing an undersized buffer to be allocated and then overrun. This affects builds using DTLS 1.3 and wolfSSL version 5.9.0 and earlier. A fix was added to the 5.9.1 release. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10116.

* [High] CVE-2026-55958
  Out-of-bounds write in the Renesas TSIP TLS 1.3 transcript buffer. In tsip_StoreMessage() the capacity check guarding the fixed message bag (MSGBAG_SIZE) sets an error code but fails to return, so execution falls through to an XMEMCPY that writes past the end of the buffer once the accumulated TLS 1.3 handshake transcript exceeds MSGBAG_SIZE (8 KB), corrupting adjacent heap state and potentially causing a remote denial of service crash. The bag is sized to hold a normal handshake, so this is reached only by an unusually large but valid certificate chain, or by a malicious or man-in-the-middle server sending an oversized handshake message to a client that does not strictly verify the chain. This only affects builds using the Renesas TSIP TLS port (WOLFSSL_RENESAS_TSIP_TLS) as a TLS 1.3 client on Renesas MCUs with TSIP hardware enabled, and is rated High within those builds. All other configurations are unaffected. Thanks to NVIDIA Project Vanessa for the report. Fixed in PR 10705.

* [High] CVE-2026-55960
  Un-negotiated Raw Public Key (RFC 7250) accepted in place of an X.509 certificate, bypassing chain validation. A raw public key has no chain, so ParseCertRelative() accepts it without performing any trust verification; it must therefore only be accepted when RPK was actually negotiated for that peer. The check now defaults the expected type to X.509 (per RFC 7250/8446) when no type was negotiated, comparing against the received server certificate type on the client and the selected client certificate type on the server, and rejects any mismatch, including an un-negotiated raw public key, with UNSUPPORTED_CERTIFICATE.  Only affects builds with Raw Public Key support (HAVE_RPK) enabled - disabled by default in a standalone build, but included in --enable-all. Thanks to NVIDIA Project Vanessa for the report. Fixed in PR 10702.

* [High] CVE-2026-55961
  wolfSSL_PKCS7_verify() returning success for a degenerate (certs-only) PKCS#7 object that contains no signer. Such an object has empty signerInfos, so the underlying signed-data verification succeeds without authenticating any content. The compatibility-layer verify path now rejects the object when no signer signature has actually been verified, so a PKCS#7 carrying no valid signature is no longer reported as verified. This is enforced regardless of the PKCS7_NOVERIFY flag, which only suppresses signer certificate chain validation and was never intended to waive the requirement that a signature exist. Only affects OpenSSL compatibility builds that call the PKCS7_verify() compatibility API on potentially degenerate PKCS#7 bundles. Thanks to NVIDIA Project Vanessa for the report. Fixed in PR 10702.

* [High] CVE-2026-10097
  wolfSSL's AVX2-optimized ML-KEM implementation (mlkem_cmp_avx2) compares only 1536 of the 1568 ciphertext bytes during the Fujisaki-Okamoto re-encryption check in ML-KEM-1024 decapsulation. Ciphertexts that differ from the expected re-encryption solely in bytes 1536-1567 bypass implicit rejection and are accepted as valid, breaking IND-CCA2 security. An attacker able to submit chosen ciphertexts to a decapsulation oracle that uses a static ML-KEM-1024 key, and to observe whether the genuine shared secret or the implicit-rejection secret was produced, can use this as a plaintext-checking oracle to recover the private key. A proof of concept recovered a full ML-KEM-1024 private key with approximately 98% success using roughly 350 chosen ciphertexts. The flaw is a deterministic logic error and does not rely on timing measurements. Thanks to 007bsd @007bsd for the report. Fixed in PR 10430.

* [Med] CVE-2026-6731
  X.509 name constraint bypass via the Subject Common Name when treated as a DNS-type name. A certificate whose Subject CN violates an issuing CA's DNS name constraints could be accepted. Thanks to d0sf3t (Aradex) for the report. Fixed in PR 10223.

* [Med] CVE-2026-6091
  Partial-chain certificate verification may accept chains that terminate at a peer-supplied, untrusted intermediate certificate rather than a trusted anchor. An attacker could present a chain that ends at an intermediate they control and have it accepted as valid. Thanks to Dikai Zou for the report. Fixed in PR 10170.

* [Med] CVE-2026-6094
  Heap buffer overread in wc_PKCS7_DecodeEnvelopedData when parsing crafted PKCS7 EnvelopedData. This could theoretically be triggered by attacker-supplied data delivered via S/MIME or CMS. Thanks to Dikai Zou for the report. Fixed in PR 10128.

* [Med] CVE-2026-6329
  PKCS#12 MAC verification uses an attacker-controlled comparison length, weakening the integrity check on the MAC and allowing a mismatched MAC to be accepted. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10192.

* [Med] CVE-2026-6330
  The ML-KEM ARM64 NEON ciphertext comparison only compares half of the input, breaking the Fujisaki-Okamoto transform's implicit rejection and weakening IND-CCA2 security on that code path. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10192.

* [Med] CVE-2026-8720
  wc_Blake2bHmacFinal and wc_Blake2sHmacFinal discard the message when the key length exceeds the block size, producing a MAC that is independent of the input. This bug is specific to the HMAC-BLAKE2 API’s that were added in wolfSSL version 5.9.0. Fixed in PR 10447.

* [Med] CVE-2026-10098
  OCSP CertID serial-number length-confusion in wolfSSL_OCSP_resp_find_status allows a same-issuer SingleResponse whose serial is a prefix of the target serial to be reported as the revocation status of a different certificate. Thanks to Kim Youngjoon (Team-Atlanta and Georgia Institute of Technology) for the report. Fixed in PR 10554.

* [Med] CVE-2026-10592
  Certificates with wildcard DNS SANs (e.g. *.example.com) bypassed CA name-constraint checks. Thanks to tonghuaroot for the report. Fixed in PR 10549.

* [Med] CVE-2026-7532
  iPAddress name constraints bypass when WOLFSSL_IP_ALT_NAME is not defined. IP address name constraints are not enforced in that configuration, allowing a certificate to bypass an issuing CA's IP address constraints. Thanks to Ankur Tyagi of Cisco Talos (TALOS-2026-2409) for the report. Fixed in PR 10354.

* [Med] CVE-2026-6291
  Bleichenbacher padding oracle in PKCS#7 KTRI decryption. When decrypting PKCS#7 EnvelopedData using RSA PKCS#1 v1.5 key transport, wolfSSL returned distinguishable error codes depending on whether RSA padding validation failed versus whether the decrypted content was malformed. An attacker able to submit crafted EnvelopedData messages and observe error responses could use this as a padding oracle to incrementally recover the encrypted Content Encryption Key (CEK). The fix generates a deterministic pseudo-random fake CEK on padding failure (via HMAC-SHA256) and proceeds with decryption identically, using constant-time operations throughout, so that all failure paths produce the same error regardless of padding validity. Found with internal wolfSSL review. Fixed in PR 10203.

* [Med] CVE-2026-7511
  PKCS7_verify signer confusion allows forged signatures, where the signer associated with a signature is not correctly bound, permitting a forged signature to be accepted. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10203.

* [Med] CVE-2026-11703
  Fixed missing SNI/ALPN binding on stateful (session-ID) resumption, which previously skipped the binding check performed for ticket-based resumption. A cached session could be resumed under a different SNI/ALPN than originally negotiated and, where client-authentication policy differs across virtual hosts, carry the cached peer-authentication state into a context it was not established for. Resumption now verifies the SNI/ALPN binding for all paths and declines (falling back to a full handshake) on mismatch. Thanks to Dikai Zou for the report. Fixed in PR 10489.

* [Med] CVE-2026-55962
  TLS 1.3 post-handshake authentication (PHA) issue where a server could accept a client's Finished message without the client having sent a Certificate and CertificateVerify. The post-handshake-auth exemption that allows an empty/absent peer certificate was only intended for the initial handshake, but it was also being applied while a post-handshake CertificateRequest was still outstanding. The check is now scoped to the initial handshake only: on the server, once a post-handshake CertificateRequest has been sent (certReqCtx is set), a peer certificate and a valid CertificateVerify are required again before the Finished is accepted, with empty-certificate handling following the configured verify mode (FAIL_IF_NO_PEER_CERT) just as during first-handshake client authentication. Only affects TLS 1.3 servers built with post-handshake authentication support (WOLFSSL_POST_HANDSHAKE_AUTH / --enable-postauth, included in --enable-all) that enable WOLFSSL_VERIFY_POST_HANDSHAKE and request a client certificate after the handshake via wolfSSL_request_certificate(). Clients, and servers that do not use post-handshake authentication, are unaffected. Thanks to NVIDIA Project Vanessa for the report. Fixed in PR 10702.

* [Med] CVE-2026-55964
  Chain intermediate CA:TRUE without keyCertSign accepted as a signing CA. Intermediate CA certificates are required to have the keyCertSign key usage when a Key Usage extension is present, but chain-supplied temporary CAs (WOLFSSL_TEMP_CA) added while building a certificate path were previously exempted from this check, so an intermediate asserting CA:TRUE but lacking keyCertSign was accepted as a signing CA. The check now applies to chain-supplied temporary CAs as well; only operator-loaded root certificates (WOLFSSL_USER_CA) and self-signed roots remain exempt. Per RFC 5280 an absent Key Usage extension implies all usages, so the requirement is enforced only when the extension is actually present (extKeyUsageSet). Affects the OpenSSL-compatibility certificate-path-building path (X509_verify_cert / X509_STORE, OPENSSL_EXTRA/OPENSSL_ALL), where untrusted chain intermediates are added as temporary CAs; native (non-OpenSSL-compat) certificate verification does not create temporary CAs and is unaffected. Within those builds, the check applies unless ALLOW_INVALID_CERTSIGN is defined. Thanks to NVIDIA Project Vanessa for the report. Fixed in PR 10702.

* [Low] CVE-2026-6092
  When HAVE_ENCRYPT_THEN_MAC is configured, the implementation could fall back to MAC-then-Encrypt rather than enforcing Encrypt-then-MAC. Thanks to Marcin Olejnik (Rockwell Automation) for the report. Fixed in PR 10167.

* [Low] CVE-2026-6331
  HMAC zero-length tag forgery in EVP_DigestVerifyFinal, where a zero-length tag could be accepted as valid during HMAC verification. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10192.

* [Low] CVE-2026-6681
  The PKCS#7 decode path ignores the caller-supplied output buffer size (outputSz), allowing decoded content to be written past the bounds of the provided buffer. This affects wolfSSL 5.9.0 and earlier and was fixed in the 5.9.1 release. Thanks to Nicholas Carlini from Anthropic for the report. Fixed in PR 10116.

* [Low] CVE-2026-10512
  The X25519 x86_64 assembly implementation fails to clear the most significant bit during the final modular reduction, so the computed result may not be fully reduced modulo the field prime 2^255 - 19. This can leave the field element in a non-canonical form, producing an incorrect result from the scalar multiplication and potentially a wrong shared secret. Thanks to Haruki Oyama for the report. Fixed in PR 10536.

* [Low] CVE-2026-6678
  Integer underflow in wc_PKCS7_DecryptOri when handling crafted Other Recipient Info, leading to incorrect length handling during decryption. Thanks to Dikai Zou for the report. Fixed in PR 10203.

* [Low] CVE-2026-7531
  Use-after-free in PQC hybrid key-share handling. This is an incomplete-fix follow-up to CVE-2026-5460 (released in 5.9.1): a malicious TLS 1.3 server sending a truncated PQC hybrid KeyShare can still trigger the error cleanup path to operate on freed memory. Thanks to Thai Duong (Calif.io / Anthropic) for the report. Fixed in PR 10327.

* [Low] CVE-2026-6325
  Out-of-bounds write in SetSuitesHashSigAlgo when processing an oversized signature algorithms list, allowing a write past the bounds of the destination buffer. Thanks to Muhammad Arya Arjuna Habibullah (Pelioro) for the report. Fixed in PR 10204.

* [Low] CVE-2026-6412
  Certificate policy and RFC 8446 compliance concerns regarding the continued acceptance of SHA-1/MD5 in certificate processing. Thanks to Xiangdong Li (Student, Beijing University of Posts and Telecommunications [BUPT]) for the report. Fixed in PR 10222.

* [Low] CVE-2026-6450
  A CRL critical extension bypass exists in ParseCRL_Extensions where critical extensions are not properly enforced, allowing a crafted CRL with an unhandled critical extension to be accepted. This only affects builds with CRL support enabled and where a crafted CRL had a trusted signature when parsed. Thanks to Oleh Konko (@1seal) for the report. Fixed in PR 10239.

* [Low] CVE-2026-12340
  Out-of-bounds heap read during SM2/SM3 certificate signature verification. When parsing a certificate with an SM3wSM2 signature, the Subject Key Identifier computation reads the trailing 65 bytes of the public key without checking that the key is at least that long. A public key shorter than 65 bytes results in an out-of-bounds heap read, leading to a potential crash (denial of service); there is no out-of-bounds write. Note this only affects builds with SM2 support (--enable-sm2 or --enable-all). Thanks to David Pokora, Trail of Bits (in collaboration with Anthropic). Fixed in PR 10641.

* [Low] CVE-2026-55967
  AES-GCM encryption/decryption with extremely large cumulative single message sizes (>64 GiB) were not properly rejected by the streaming APIs, allowing counter wrap, keystream reuse, and consequent plaintext recovery. Thanks to NVIDIA Project Vanessa for the report. Fixed in PR 10709.
