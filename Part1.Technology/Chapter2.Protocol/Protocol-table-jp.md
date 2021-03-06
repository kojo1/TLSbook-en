|名前 |ID|
|:---:|:---:|
|TLS_AES_128_GCM_SHA256|0x1301|
|TLS_AES_256_GCM_SHA384|0x1302|
|TLS_CHACHA20_POLY1305_SHA256|0x1303|
|TLS_AES_128_CCM_SHA256|0x1304|
|TLS_AES_128_CCM_8_SHA256|0x1305|

表2-2 TLS1.3の暗号スイート

---
<br>

|グループ| 署名アルゴリズム	| ID	| 
|:----|:----:|:----:|
|ECDHE   |||
|        |secp256r1|0x0017|
|        |secp384r1|0x0018|
|        |secp521r1|0x0019|
|        |x25519|0x001D|
|        |x448|0x001E|
|DHE     |||
|        |ffdhe2048|0x0100|
|        |ffdhe3072|0x0101|
|        |ffdhe4096|0x0102|
|        |ffdhe6144|0x0103|
|        |ffdhe8192|0x0104|
|Reserved|||
|        |ffdhe_private_use|0x01FC..0x01FF|
|        |ecdhe_private_use|0xFE00..0xFEFF|

<br>


表2-3 Supported Groupで使用される主なGroupとID一覧

---
<br>

|グループ| 署名アルゴリズム(暗号スイート名)	| ID	| 
|:----|:----:|:----:|
|RSASSA PKCS#1 v1.5|                     |        |
|                  | rsa_pcks1_sha256    | 0x0401 |
|                  | rsa_pcks1_sha384    | 0x0501 |
|                  | rsa_pcks1_sha512    | 0x0601 |
|ECDSA             |                     |        |
|                  | ecdsa_secp256r1     | 0x0403 |
|                  | ecdsa_secp384r1     | 0x0503 |
|                  | ecdsa_secp521r1     | 0x0603 |
|RSASSA-PSS pub-key OID rsaEncryption   ||        |
|                  | rsa_pss_rsae_sha256 | 0x0804 |
|                  | rsa_pss_rsae_sha384 | 0x0805 |
|                  | rsa_pss_rsae_sha256 | 0x0806 |
|EdDSA             |                     |        |
|                  | ed25519             | 0x0807 |
|                  | ed448               | 0x0808 |
|RSASSA-PSS pub-key OID RSASSA-PSS      ||        |
|                  | rsa_pss_pss_sha256  | 0x0809 |
|                  | rsa_pss_pss_sha384  | 0x080a |
|                  | rsa_pss_pss_sha512  | 0x080b |

<br>

表2-4 TLS1.3 で使用できる署名アルゴリズム一覧

---
