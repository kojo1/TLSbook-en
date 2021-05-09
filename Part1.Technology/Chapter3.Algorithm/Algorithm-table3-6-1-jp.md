|分類　　|パディング|略称|機能|説明|
|---|---|---|---|---|
|鍵タイプ|||公開鍵|公開鍵の基本要素(n, e)|
|        |||秘密鍵形式1|簡易秘密鍵の<br>基本要素(n, d)|
|        |||秘密鍵形式2|秘密鍵の基本要素(p, q, dP, dQ, qInv)|
|データ変換プリミティブ||I2OSP |整数八進プリミティブ|整数から八進変換|||
|　　　　　　　　　　　　||OS2IP |八進整数プリミティブ|八進から整数変換|||
|暗号プリミティブ||RSAEP|暗号化プリミティブ|公開鍵によるパディング無暗号化|||
|            ||RSADP|復号化プリミティブ|秘密鍵形式１、２によるパディング無復号化|||
|            ||RSASP1|署名プリミティブ|秘密鍵によるパディング無署名|
|            ||RSAVP1|検証プリミティブ|公開鍵によるパディング無検証|
|暗号スキーム|OAEP|RSAES-OAEP|暗号化オペレーション|OAEPパディング公開鍵による暗号化|
|　　　　|||復号化オペレーション|OAEPパディング秘密鍵による復号化|
||v1.5|RSAES-PKCS1-v1_5|暗号化オペレーション|v1.5パディング公開鍵による暗号化|
|　　　　|||復号化オペレーション|v1.5パディング秘密鍵による復号化|
|メッセージ署名スキーム|PSS|RSAES-PSS |署名オペレーション|　PSSパディング秘密鍵による署名||
|　　　　              |||検証オペレーション　|　PSSパディング公開鍵による検証|
||v1.5|RSAES-PKCS1-v1_5|署名オペレーション|v1.5パディング秘密鍵による署名||
|　　　　              |||検証オペレーション　|v1.5パディング公開鍵による検証|
|エンコード方式|PSS|EMSA-PSS|エンコードオペレーション|PSSパディング|
|　　　　|||検証オペレーシ　　　|PSSパディングの検証|
||v1.5|EMSA-PKCS1-v1_5|エンコードオペレーション|v1.5パディング|


<br>
表3-6-1 PKCS#1 (RFC8017)のRSA公開鍵スキーム

<br>
<br>


<br>

|ハッシュ|備考|
|---|---|
|SHA1||

表3-6-3 マスク生成関数(MGF1)のハッシュオプション一覧
