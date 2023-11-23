#!/bin/bash

# Define entity info
clients_array=("alice" "bob" "carol")

# Issued Questionaire Answers
owner_name="Tomé Filipe Vasco da Costa" # First and Last name
owner_org_unit=di # Name of Organizational Unit
owner_org=fct # Name of your Organization
owner_city=almada # Name of City
owner_district=setubal # Name of State or Province
owner_country_code=pt # Country two letter code

# Main Dispatcher
md_alias=md
md_keystore=md.jks
md_cert=md.cer
md_storepass=md123456
md_foldername=mdCrypto

# Authentication Server
as_alias=as
as_keystore=as.jks
as_cert=as.cer
as_storepass=as123456
as_foldername=asCrypto

# Access Control Server
ac_alias=ac
ac_keystore=ac.jks
ac_cert=ac.cer
ac_storepass=ac123456
ac_foldername=acCrypto

# Storage Server
ss_alias=ss
ss_keystore=ss.jks
ss_cert=ss.cer
ss_storepass=ss123456
ss_foldername=ssCrypto

# Client Model
cl_alias=cl
cl_keystore=cl.jks
cl_cert=cl.cer
cl_storepass=cl123456
cl_foldername=clients

# Define functions
resetFolder(){
    rm -r $1
    mkdir $1
}

genSelfSignedKeysAndCerts(){
    # 1-alias, 2-keystore, 3-cert, 4-storepass, 5-folder path

    # Start
    cd $5

    # Generate a self-signed keystore
    printf "$owner_name\n$owner_org_unit\n$owner_org\n$owner_city\n$owner_district\n$owner_country_code\nyes\n" |\
    keytool -genkeypair -noprompt -keyalg RSA -alias $1 -keystore "selfsigned" -storepass $4 -validity 360 -keysize 4096

    # Convert keystore from PKCS12
    printf "${4}\n${4}\n${4}\n" |\
    keytool -importkeystore -srckeystore selfsigned -srcstoretype PKCS12 -destkeystore "keystore_${2}" -deststoretype JKS
    rm selfsigned

    # Generate a certificate from the self-signed keystore
    printf "${4}\n" |\
    keytool -export -alias $1 -keystore "keystore_${2}" -file $3

    # Create .pem from .cer
    openssl x509 -inform der -in $3 -out $1.pem

    # Create .key file with private key
    printf "${4}\n${4}\n${4}\n" |\
    keytool -v -importkeystore -srckeystore keystore_${2} -destkeystore k.p12 -deststoretype PKCS12

    openssl pkcs12 -nocerts -in k.p12 -out privkey.pem -passin pass:$4 -passout pass:$4

    openssl rsa -in privkey.pem -out ${1}_priv.key -passin pass:$4 -passout pass:$4

    rm k.p12
    rm privkey.pem

    cd ..
}

addAllToMainDispatcherTrustore(){
    cd $md_foldername

    # Add other servers
    printf "${md_storepass}\n${md_storepass}\nyes\n" |\
    keytool -import -alias $as_alias -file "../${as_foldername}/${as_cert}" -keystore truststore # AS

    printf "${md_storepass}\nyes\n" |\
    keytool -import -alias $ac_alias -file "../${ac_foldername}/${ac_cert}" -keystore truststore # AC

    printf "${md_storepass}\nyes\n" |\
    keytool -import -alias $ss_alias -file "../${ss_foldername}/${ss_cert}" -keystore truststore # SS

    # Add clients
    for client_name in "${clients_array[@]}"; do
        printf "${md_storepass}\nyes\n" |\
        keytool -import -alias "${client_name}_${cl_alias}" -file "../clients/${client_name}Crypto/${client_name}_${cl_cert}" -keystore truststore # Client
    done

    printf "${md_storepass}\n${md_storepass}\n${md_storepass}\n" |\
    keytool -importkeystore -srckeystore truststore -srcstoretype PKCS12 -destkeystore ${md_alias}_truststore -deststoretype JKS

    rm truststore

    cd ..
}

addMainDispatcherToServerTruststore(){
    cd $2

    # 1- alias, 2- folder, 3- storepass
    printf "${3}\n${3}\nyes\n" |\
    keytool -import -alias $md_alias -file "../${md_foldername}/${md_cert}" -keystore truststore

    printf "${3}\n${3}\n${3}\n" |\
    keytool -importkeystore -srckeystore truststore -srcstoretype PKCS12 -destkeystore ${1}_truststore -deststoretype JKS

    rm truststore

    cd ..
}

addMainDispatcherToClientTruststore(){
    cd $2

    # 1- alias, 2- folder, 3- storepass
    printf "${3}\n${3}\nyes\n" |\
    keytool -import -alias $md_alias -file "../../${md_foldername}/${md_cert}" -keystore truststore

    printf "${3}\n${3}\n${3}\n" |\
    keytool -importkeystore -srckeystore truststore -srcstoretype PKCS12 -destkeystore ${1}_truststore -deststoretype JKS

    rm truststore

    cd ..
}

# Reset folders
resetFolder $md_foldername
resetFolder $as_foldername
resetFolder $ac_foldername
resetFolder $ss_foldername
resetFolder $cl_foldername

# Entities
genSelfSignedKeysAndCerts $md_alias $md_keystore $md_cert $md_storepass $md_foldername
genSelfSignedKeysAndCerts $as_alias $as_keystore $as_cert $as_storepass $as_foldername
genSelfSignedKeysAndCerts $ac_alias $ac_keystore $ac_cert $ac_storepass $ac_foldername
genSelfSignedKeysAndCerts $ss_alias $ss_keystore $ss_cert $ss_storepass $ss_foldername

echo
echo
echo "Servers' Info Generated..."
sleep 1

# Gen for clients too
cd $cl_foldername
for client_name in "${clients_array[@]}"; do
    mkdir "./${client_name}Crypto"
    genSelfSignedKeysAndCerts "${client_name}_${cl_alias}" "${client_name}_${cl_keystore}" "${client_name}_${cl_cert}" $cl_storepass \
    ${client_name}Crypto
done
cd ..

# clients
    # alice
    # bob

echo
echo
echo "Clients' Info Generated..."
sleep 3

# Add to truststores
addAllToMainDispatcherTrustore

addMainDispatcherToServerTruststore $as_alias $as_foldername $as_storepass
addMainDispatcherToServerTruststore $ac_alias $ac_foldername $ac_storepass
addMainDispatcherToServerTruststore $ss_alias $ss_foldername $ss_storepass

cd $cl_foldername
for client_name in "${clients_array[@]}"; do
    addMainDispatcherToClientTruststore "${client_name}_${cl_alias}" ${client_name}Crypto $cl_storepass
done
cd ..

# Finish
echo "Process Finished"