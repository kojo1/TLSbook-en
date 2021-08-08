# 7. 暗号アルゴリズム

本章では、各種の暗号アルゴリズムについてサンプルプログラムを紹介します。

###　共通ラッパー
この章のプログラムはコマンドとして動作するように、共通のラッパーとして動作するmain関数を用意しています。common/cipher_main.cにその内容が格納されています。cipher_main.cのmain関数は一連のアーギュメントのチェックと解析を行いcipher_main関数を呼び出します。
cipher_main関数はアルゴリズムサンプルごとの個別の関数です。このラッパーを使用することにより、個別のアルゴリズムの関数は、アルゴリズムのための固有の処理だけを行うことができます。

このラッパー関数を使ったコマンドは以下のアーギュメントを受け付けます。

- 第一アーギュメント：入力ファイル名
- 第二アーギュメント：出力ファイル名(省略可)

以下のオプションアーギュメント：
- -e : 暗号化処理
- -d : 復号処理
- -k : 次のアーギュメントで１６進の鍵値を指定
- -i : 次のアーギュメントで１６進のIV値を指定
- -t : 次のアーギュメントで１６進のタグ値を指定

ラッパーとしては -e, -d で示されたモード、-k, -i, -tで指定された任意の長さの１６進値をcipher_mainに引き渡します。
サイズが適切かどうかは個々のcipher_mainにてチェックします。
オプションアーギュメントの必要性はアルゴリズム個別処理内で判定します。

cipher_main関数は、cipher_main.h内で以下のように定義されています。cipher_main.c内のmain関数はアーギュメントの解析内容をcipher_main関数のアーギュメントに引き継ぎます。

```
void cipher_main(int mode, FILE *infp, FILE *outfp,
                 unsigned char *key, int key_sz, 
                 unsigned char *iv,  int iv_sz,
                 unsigned char *tag, int tag_sz
                );
```

# 7.1 ランダム
    RAND_bytes();
    RAND_pseudo_bytes();
    
# 7.2 ハッシュ

    SHA256_Init();
    while(fread(stdin)) {
        SHA256_Update();
    }
    SHA256_Final();
    fwrite(stdout);

# 7.3 MAC

    HMAC_Init_ex();
    while(fread(stdin)) {
        HMAC_Update();
    }
    HMAC_Final();
    fwrite(stdout);

# 7.4 共通鍵暗号

OpenSSL/wolfSSLでは、共通鍵暗号の処理のために"EVP"で始まる一連の関数が用意されています。このセクションでは、このEVP関数の一般規則とそれを使用した共通鍵暗号のプログラム例について解説します。

## 1) 全体の流れ

処理のはじめに"CTX_new"関数により処理コンテクストを管理するための管理ブロックを確保します。次に"Init"関数により初期設定関数で確保したコンテクストに対して鍵、IVなどのパラメータを設定します。

暗号化復号化処理は"Update"関数によって行います。メモリー上の入力バッファに対して処理が行われ、出力バッファに出力されます。メモリーサイズの制限が許す場合は入力データ全体を一括して"Update"関数に渡すことができますが、制限がある場合は適当な大きさに区切って"Update"関数を複数回呼び出すこともできます。その際ブロック型暗号のブロックサイズを気にすることなく、適当な処理サイズを指定することができます。このため、かならず最後に"Final"関数により半端なデータに対するパディングを処理を行う必要があります。

最後に終了後管理ブロックを解放します。

## 2) EVP関数の命名規則

EVP関数では、共通鍵の暗号または復号処理の方向がプログラミング時に静的に決定している場合のための関数と実行時に動的に決めることができる関数の二つの系列の関数が用意されています。静的な場合は関数名に"Encrypt"または"Decrypt"の命名が含まれていて、処理の方向を表します。動的な場合は関数名には"Cipher"の命名がされ、EVP_CipherInitの初期設定時に処理の方向を指定します。次の表に、これらの共通鍵処理のための関数名をまとめます。

|機能|暗号化|復号|動的指定|
|---|---|---|---|
|コンテクスト確保|EVP_CIPHER_CTX_new|EVP_CIPHER_CTX_new|EVP_CIPHER_CTX_new|
|初期設定|EVP_EncryptInit|EVP_DecryptInit|EVP_CipherInit|
|暗号/復号|EVP_EncryptUpdate|EVP_DecryptUpdate|EVP_CipherUpdate|
|終了処理|EVP_EncryptFinal|EVP_DecryptFinal|EVP_CipherFinal|
|コンテクスト解放|EVP_CIPHER_CTX_free|EVP_CIPHER_CTX_free|EVP_CIPHER_CTX_free|


## 3) パディング処理
EVP関数では、ブロック型暗号のためのパディング処理を自動的に行います。パディングスキームはPKCSです。このため、暗号化処理の場合は処理結果は入力データのサイズに比べてブロックサイズの整数倍にアラインされる分だけ大きくなる点に注意が必要です。入力データがブロックサイズの整数倍の場合にもパディング用に１ブロック分の出力データが付加されます。一方、復号化の際はパディングの内容が解消され、復号化された本来の出力データのみとなります。パディングを含んだ暗号、復号処理の出力データサイズは"Final"関数のアーギュメントに返却されます。

パディングスキームにはPKCS#7に規定されるスキームが使用されます　(3.4 共通鍵暗号 4)パディングスキーム参照)。


## 4) サンプルプログラム

以下に動的モードの場合にEVP関数を使用して共通鍵暗号処理を実現するサンプルプログラムを示します。"CIPHER" 定数の定義を変更することで各種の暗号アルゴリズム、利用モードを処理することができます。（指定できる暗号スイートについては"6) 暗号アルゴリズム、利用モード"を参照）

動作可能なサンプルコードはExamples/2.Chrypto/sym/aes-cbc.c を参照してください。このプログラムでは次のコマンドアーギュメントを受付ます。


- 入力ファイル：指定されたファイル名のファイルを入力データとして使用します。<br>
- 出力ファイル：指定されたファイル名のファイルに結果のデータを出力します。省略した場合、標準出力に出力します。<br>

- "-e"は暗号化、"-d"は複合を指定します。指定のない場合は暗号化処理をします。<br>
- "-k" の次のアーギュメントで鍵値を１６進数で指定します。<br>
- "-i" の次のアーギュメントでIV値を１６進数で指定します。<br>
<br><br><br>

```
#define CIPHER EVP_aes_128|CBC()

    コマンドアーギュメントの処理

    evp = EVP_CIPHER_CTX_new(); /* コンテクスト確保 */
    EVP_CipherInit(evp, CIPHER, key, iv, mode);  /* アルゴリズム、鍵、IV、モードの設定 */

    for( ; size > 0; size -= BUFF_SIZE) {
        inl = fread(in, 1, BUFF_SIZE, infp); 
        in[inl] = '\0';
        EVP_CipherUpdate(evp, out, &outl, in, inl); /*　暗号、復号 */
        fwrite(out, 1, outl, outfp);
    }
    EVP_CipherFinal(evp, out, &outl); /* パディング処理 */
    fwrite(out, 1, outl, outfp);

    EVP_CIPHER_CTX_free(evp);
```         
<br><br><br>

## 5) 認証付き暗号(AEAD)

AES-GCMなど認証付き暗号の場合は認証タグを取扱う必要があります。下のプログラムで示すように、暗号化の際は、"Final"の後に復号の際に使用する認証タグを得ておきます。復号の際は、"Final"の前にそのタグを設定します。"Final"処理の返却値が成功であることで認証タグの検証が成功したことを確認します。
<br><br><br>
動作可能なサンプルコードはExamples/2.Chrypto/sym/aes-cbc.c を参照してください。このプログラムでは次のコマンドアーギュメントを受付ます。


- 入力ファイル：指定されたファイル名のファイルを入力データとして使用します。<br>
- 出力ファイル：指定されたファイル名のファイルに結果のデータを出力します。省略した場合、標準出力に出力します。<br>

- "-e"は暗号化、"-d"は複合を指定します。指定のない場合は暗号化処理をします。<br>
- "-k" の次のアーギュメントで鍵値を１６進数で指定します。<br>
- "-i" の次のアーギュメントでIV値を１６進数で指定します。<br>
- "-t" の次のアーギュメントでタグ値を１６進数で指定します。<br>

```
   コマンドアーギュメントの処理

    evp = EVP_CIPHER_CTX_new(); /* コンテクスト確保 */
    EVP_CipherInit(evp, CIPHER, key, iv, mode);  /* アルゴリズム、鍵、IV、モードの設定 */

    for( ; size > 0; size -= BUFF_SIZE) {
        inl = fread(in, 1, BUFF_SIZE, infp); 
        in[inl] = '\0';
        EVP_CipherUpdate(evp, out, &outl, in, inl); /*　暗号、復号 */
        fwrite(out, 1, outl, outfp);
    }

    if(mode == DEC) /* 復号処理ならば認証用タグを設定 */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, outTag1Part);

    if(EVP_CipherFinal(evp, out, &outl) != SSL_SUCCESS) /* パディング処理 */
        エラー処理
    else
        fwrite(out, 1, outl, outfp);

    if(mode == ENC) /* 暗号処理ならばタグを得る */
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, outTag1Part);
    
    EVP_CIPHER_CTX_free(evp);


```
<br><br><br>

## 6) 暗号アルゴリズム、利用モード

EVPでは各種の暗号アルゴリズム、利用モードなどの処理パラメータの設定を"Init"関数で行うことで、処理を統一的に取り扱うことができます。以下に"Init"にて指定できる主な暗号スイートをまとめます。

|シンボル|アルゴリズム|ブロック長|鍵長|利用モード|
|---|---|---|---|---|
|EVP_aes_xxx_cbc   |AES|128|xxx: 128, 192, 256|CBC|
|EVP_aes_xxx_cfb1  |AES|128|xxx: 128, 192, 256|CFB1|
|EVP_aes_xxx_cfb8  |AES|128|xxx: 128, 192, 256|CFB8|
|EVP_aes_xxx_cfb128|AES|128|xxx: 128, 192, 256|CFB128|
|EVP_aes_xxx_ofb   |AES|128|xxx: 128, 192, 256|OFB|
|EVP_aes_xxx_xts   |AES|128|xxx: 128, 256|XTS|
|EVP_aes_xxx_gcm   |AES|128|xxx: 128, 192, 256|GCM|
|EVP_aes_xxx_ecb   |AES|128|xxx: 128, 192, 256|ECB|
|EVP_aes_xxx_ctr   |AES|128|xxx: 128, 192, 256|CTR|
|EVP_des_cbc       |DES|64|56|CBC|
|EVP_des_ecb       |DES|64|56|ECB|
|EVP_des_ede3_cbc  |DES-EDE3|64|168|CBC|
|EVP_des_ede3_ecb  |DES-EDE3|64|168|ECB|
|EVP_idea_cbc      |IDEA|64|128|CBC|
|EVP_rc4           |RC4||||

## 7) 関連API


<br>
以下に共通鍵暗号の処理に関連する主なEVP関数をまとめます。
<br>

|関数名|機能|
|---|---|
|EVP_CIPHER_CTX_iv_length, EVP_CIPHER_iv_length        |IVサイズを取得|
|EVP_CIPHER_CTX_key_length, EVP_CIPHER_key_length      |鍵サイズを取得|
|EVP_CIPHER_CTX_mode, EVP_CIPHER_mode        |暗号、復号のモードを取得|
|EVP_CIPHER_CTX_block_size, EVP_CIPHER_block_size   |ブロックサイズを取得|
|EVP_CIPHER_CTX_flags, EVP_CIPHER_flags       |フラグを取得|
|EVP_CIPHER_CTX_cipher      |アルゴリズムを取得|
|EVP_CIPHER_CTX_set_key_length |鍵サイズを設定|
|EVP_CIPHER_CTX_set_iv      |IVサイズを設定|
|EVP_CIPHER_CTX_set_padding |パディングを設定|
|EVP_CIPHER_CTX_set_flags   |フラグを設定|
|EVP_CIPHER_CTX_clear_flags |フラグをクリア|
|EVP_CIPHER_CTX_reset       |コンテクストをリセット<br>(後方互換：EVP_CIPHER_CTX_FREEで不要に)|
|EVP_CIPHER_CTX_cleanup     |コンテクストをクリーンアップ<br>(後方互換：EVP_CIPHER_CTX_FREEで不要に)|



# 7.5 公開鍵暗号/復号

    暗号化
    fread(stdin);
    EVP_PKEY_CTX_set_rsa_padding();
    EVP_PKEY_encrypt();
    fwrite(sdiout);

    復号
    fread(stdin);
    EVP_PKEY_CTX_set_rsa_padding();
    EVP_PKEY_decrypt();
    fwrite(sdiout);

# 7.6 公開鍵署名
# 7.6.1 RSA署名
    署名
    EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    EVP_DigestSignInit();
    while(fread(stdin)) {
        EVP_DigestSignUpdate();
    }
    EVP_DigestSignFinal();

    検証

# 7.6.2 ECDSA署名
    署名
    EVP_PKEY_new();
    EVP_PKEY_assign_EC_KEY();
    EVP_DigestSignInit();
    while(fread(stdin)) {
        EVP_DigestSignUpdate();
    }
    EVP_DigestSignFinal();

    検証

# 7.7 鍵合意

    EVP_PKEY_CTX_new_id();
    EVP_PKEY_paramgen_init();
    EVP_PKEY_paramgen();

    EVP_PKEY_CTX_new();

    EVP_PKEY_keygen_init();
    EVP_PKEY_keygen();


    EVP_PKEY_CTX_new();
    EVP_PKEY_derive_init();
    EVP_PKEY_derive_set_peer();
    EVP_PKEY_derive();





