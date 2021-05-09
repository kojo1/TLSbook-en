## TLS 1.3のTLS拡張一覧
<br>

|拡張タイプ| 概要|RFC|拡張が含まれるTLSメッセージ|
|:--:|:--:|:--|:--:|
|server_name<br>(SNI)|セッション再開時の照合要素として利用|6066|ClientHello, EncryptedExtensions|
|max_fragment_length|メッセージの最大フラグメントサイズ|6666|ClientHello, EncryptedExtensions|
|status_request|Online Certificate Status Protocol(OCSP)によるレスポンスを要求する|6666|ClientHello, CertificateRequest, Certificate|
|supported_groups|使用したい鍵交換スキームリスト|8422, 7919|ClientHello, EncryptedExtensions|
|signature_algorithms|署名アルゴリズム|8446|ClientHello, CertificateRequest|
|signature_algorithms_cert|証明書の署名アルゴリズム|8446|ClientHello, CertificateRequest|
|use_srtp|Secure Real-time Transport Protocol(SRTP) プロファイルのリスト|5764|ClientHello, EncryptedExtensions|
|heartbeat|ハートビートの送信モードの提示|6520|ClientHello, EncryptedExtensions|
|application_layer_protocol_negotiation<br> (ALPN)|サポートしているアプリケーションプロトコル名のリスト|7301|ClientHello, EncryptedExtensions|
|signed_certificate_timestamp|(編集中）|6962|ClientHello, CertificateRequest, Certificate|
|client_certificate_type|(編集中）|7250|ClientHello, EncryptedExtensions|
|server_certificate_type|(編集中）|7250|ClientHello, EncryptedExtensions|
|padding|(編集中）|7685|ClientHello|
|psk_key_exchange_modes|PSKのみ/鍵交換付きPSKの提示|8446|ClientHello|
|pre_shared_key|(編集中）|8446|ClientHello, ServerHello|
|early_data|(編集中）|8446|ClientHello, EncryptedExtensions, NewSessionTicket|
|supported_versions|クライアントがサポートしているTLSバージョン提示|8446|ClientHello, ServerHello, HelloRetryRequest|
|cookie|サーバーがHRRに指定しクライアントがHRで返送|8446|ClientHello, HelloRetryRequest|
|certificate_authorities|サポートしてるCA認証局名リスト|8446|ClientHello, CertificateRequest|
|oid_filters|証明書拡張OIDと値の組|8446|CertificateRequest|
|post_handshake_auth|クライアントがPHAを要求する意を示す|8446|ClientHello|
|key_share|各鍵交換スキーム用パラメターのリスト|8446|ClientHello, ServerHello, HelloRetryRequest|
