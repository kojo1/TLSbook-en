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
# 7.4.1 AES-CBC
    暗号化
    while(fread(stdin)) {
        EVP_encrypt();
        fwrite(stdout);
    }

# 7.4.2 AES-GCM
    暗号化
    while(fread(stdin)) {
        EVP_encrypt();
        fwrite(stdout);
    }

    複合化
    while(fread(stdin)) {
        EVP_decrypt();
        fwrite(stdout);
    }

# 7.5 公開鍵暗号/復号

    暗号化
    fread(stdin);
    EVP_PKEY_CTX_set_rsa_padding();
    EVP_PKEY_encrypt();
    fwrite(sdiout);

    複合化
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





