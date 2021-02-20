

| Year	| Version	| IETF RFC| 
| ---- | ---- | :----: |
| 1996| 	SSLv3.0|    --- | 
| 1999| 	TLS1.0| 	RFC2246| 
| 2006| 	TLS1.1| 	RFC4346|
| 2008| 	TLS1.2| 	RFC5246| 
| 2018| 	TLS1.3| 	RFC8446| 
        SSL, TLSの経緯


| 名前	| 攻撃手法	| 原因	| 解決| 
| ---- | ---- | ---- | ---- |
| SLOTH	| ハッシュ衝突	| 危殆化したハッシュ	| アルゴリズム廃止|
| SWEET32	| ブロック暗号衝突	| 危殆化した共通鍵暗号	| アルゴリズム廃止| 
| CurveSwap	| ダウングレード	| 署名範囲	| 署名範囲拡大| 
| LogJam	| ダウングレード	| 署名範囲	| 署名範囲拡大| 
| FREAK	| ダウングレード	| 署名範囲	| 署名範囲拡大| 
| POODLE	| パディングオラクル	| 共通鍵暗号とMAC	| AEAD| 
| BEAST	| パディングオラクル	| 共通鍵暗号とMAC	| AEAD| 
| Lucky 13	| パディングオラクル	| 共通鍵暗号とMAC	| AEAD| 
| Lucky Microseconds	| パディングオラクル	| 共通鍵暗号とMAC	| AEAD| 
| WeakDH	| DHパラメータ	| DHパラメータの自由度	| サポートグループ| 
| pen-and-paper	| RSAパディング	| PKCS#v1.5	| PSS| 
| ROBOT	| RSAプライベート鍵| 	静的RSA	| 一時鍵DH| 
| million-message	| RSAプライベート鍵	| 静的RSA	| 一時鍵DH| 

            TLS1.3のモチベーションとなった主な攻撃手法、脆弱性

