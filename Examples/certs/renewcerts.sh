#!/bin/bash
# renews the following certs:
#  tb-ca-cert.pem
#  tb-server-cert.pem
#

check_result(){
    if [ $1 -ne 0 ]; then
        echo "Failed at \"$2\", Abort"
        if [ "$2" = "configure for ntru" ] || \
           [ "$2" = "make check with ntru" ]; then
            restore_config
        fi
        exit 1
    else
        echo "Step Succeeded!"
    fi
}

############################################################
########## update the self-signed tb-ca-cert.pem ###########
############################################################
echo "Updating tb-ca-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e  "JP\\nTOKYO\\nTOKYO\\nWolfSSL Japan\\nConsulting\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key tb-ca-key.pem -config ./tls-book-cert.cnf -nodes -out tb-ca-cert.csr
check_result $? "Step 1"

openssl x509 -req -in tb-ca-cert.csr -days 1000 -signkey tb-ca-key.pem -out tb-ca-cert.pem
check_result $? "Step 2"
rm tb-ca-cert.csr

openssl x509 -in tb-ca-cert.pem -text > tmp.pem
check_result $? "Step 3"
mv tmp.pem tb-ca-cert.pem
echo "End of section"
echo "---------------------------------------------------------------------"

###########################################################
########## update and sign tb-server-cert.pem #############
###########################################################
echo "Updating server-cert.pem"
echo ""
#pipe the following arguments to openssl req...
echo -e  "JP\\nTOKYO\\nTOKYO\\nWolfSSL Japan\\nSupport\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key tb-server-key.pem -config ./tls-book-cert.cnf -nodes > tb-server-req.pem
check_result $? "Step 1"

openssl x509 -req -in tb-server-req.pem -days 1000 -CA tb-ca-cert.pem -CAkey tb-ca-key.pem -set_serial 01 > tb-server-cert.pem
check_result $? "Step 2"

rm tb-server-req.pem

openssl x509 -in tb-ca-cert.pem -text > ca_tmp.pem
check_result $? "Step 3"
openssl x509 -in tb-server-cert.pem -text > srv_tmp.pem
check_result $? "Step 4"
mv srv_tmp.pem tb-server-cert.pem
cat ca_tmp.pem >> tb-server-cert.pem
rm ca_tmp.pem
echo "End of section"
echo "---------------------------------------------------"

