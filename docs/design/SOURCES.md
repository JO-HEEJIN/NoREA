# 출처

ProvGuard ADR(2026-11-08, 이전 세션)에서 옮겨 왔다. 이번 설계에서 이 링크들을 다시 열어 확인하지 않았다. 어떤 WP에서 이 출처에 의존하는 결정을 할 때는 원문을 열어 제목과 내용을 대조하고 "확인함/불일치"를 적는다.

| # | 주제 | URL | 의존하는 결정 | 재확인 |
|---|---|---|---|---|
| 1 | NIST IR 8547 final (PQC 전환 일정) | https://nvlpubs.nist.gov/nistpubs/ir/2026/NIST.IR.8547.pdf | ADR-0003 | 미확인 |
| 2 | TCG TPM 2.0 v1.85 PQC | https://trustedcomputinggroup.org/new-computing-specification-implements-pqc-measures-to-protect-users-from-quantum-attacks/ | ADR-0006 | 미확인 |
| 3 | SEALSQ QVault TPM 일정 | https://quantumcomputingreport.com/?p=45808 | ADR-0006 | 미확인 |
| 4 | Windows PQC 일정(CNG/SymCrypt) | https://www.encryptionconsulting.com/microsoft-pqc-roadmap-windows-11-windows-server-2025/ | ADR-0006 | 미확인 |
| 5 | CNG `BCRYPT_PQDSA_PADDING_INFO` (context) | https://learn.microsoft.com/ko-kr/windows/win32/SecCNG/bcrypt/ns-bcrypt-bcrypt_pqdsa_padding_info | ADR-0003 | 미확인 |
| 6 | CryptoKit SecureEnclave MLDSA `signature(for:context:)` | https://developer.apple.com/documentation/cryptokit/secureenclave/mldsa87/privatekey/signature(for:context:) | ADR-0003, 0006 | 미확인. MLDSA65 SE 문서는 별도 확인 필요 |
| 7 | Apple quantum-secure workflows | https://developer.apple.com/documentation/cryptokit/enhancing-your-app-s-privacy-and-security-with-quantum-secure-workflows | ADR-0006 | 미확인 |
| 8 | Apple Platform Security, quantum-secure | https://support.apple.com/guide/security/secc7c82e533/web | ADR-0006 | 미확인 |
| 9 | NIST pqc-forum, FIPS 204 vs Dilithium | https://groups.google.com/a/list.nist.gov/g/pqc-forum/c/haG8Wlh2zPE | ADR-0003 | 미확인 |
| 10 | WebAuthn PRF 지원 현황 | https://www.corbado.com/blog/passkeys-prf-webauthn | custody-web-v1 | 미확인 |
| 11 | Tauri 2 (mobile, Swift/Kotlin plugins) | https://v2.tauri.app/blog/roadmap-to-tauri-2-0/ | ADR-0007 | 미확인 |
| 12 | RFC 4998 archive timestamp renewal 해설 | https://census-labs.com/resources/digitally-signed-documents-in-the-quantum-era-preserve-dont-re-sign | ADR-0004 | 미확인 |
| 13 | Cloudflare PQ 적용률 | https://blog.cloudflare.com/post-quantum-visibility/ | 배경 | 미확인 |
| 14 | 부정경쟁방지법 (파)목 연구 | https://scholar.kyobobook.co.kr/article/detail/4010069846008 | ADR-0001 | 미확인 |

표준 문서(링크 없이 번호로 인용):
- FIPS 204 (ML-DSA), RFC 5869 (HKDF), RFC 2104 (HMAC), RFC 8439 (ChaCha20-Poly1305), RFC 9162 (CT v2, Merkle tree), RFC 3161 (TSP), RFC 4998 (ERS), RFC 4180 (CSV), RFC 3339 (timestamps), RFC 4648 (base64), RFC 8785 (JCS, 채택하지 않음), UAX #15 (Unicode Normalization).
- opentimestamps-client README (https://github.com/opentimestamps/opentimestamps-client) — 확인함 2026-11-09(WebFetch). 제목 "OpenTimestamps Client". `ots verify README.md.ots` 형식이며 대상 파일명을 proof 이름에서 추정("Assuming target filename is 'README.md'"). `-f` 옵션은 README에 없음. digest 직접 지정 방법은 미확인(WP-08 단계 0).
