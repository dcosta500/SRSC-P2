#!/bin/bash

# Define entity info
clients_array=("alice" "bob" "carol" "david" "eric")

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
    keytool -genkeypair -noprompt -keyalg RSA -alias $1 -keystore "selfsigned" -storepass $4 -validity 360 -keysize 2048

    # Convert keystore from PKCS12
    printf "${4}\n${4}\n${4}\n" |\
    keytool -importkeystore -srckeystore selfsigned -srcstoretype PKCS12 -destkeystore "keystore_${2}" -deststoretype JKS
    rm selfsigned

    # Generate a certificate from the self-signed keystore
    printf "${4}\n" |\
    keytool -export -alias $1 -keystore "keystore_${2}" -file $3

    cd ..
}

addAllServersToAllOtherServersTruststores(){
    #as
    cd $as_foldername

    printf "${as_storepass}\n${as_storepass}\nyes\n" |\
    keytool -import -alias $md_alias -file "../${md_foldername}/${md_cert}" -keystore truststore # MD

    printf "${as_storepass}\nyes\n" |\
    keytool -import -alias $ac_alias -file "../${ac_foldername}/${ac_cert}" -keystore truststore # AC

    printf "${as_storepass}\nyes\n" |\
    keytool -import -alias $ss_alias -file "../${ss_foldername}/${ss_cert}" -keystore truststore # SS

    printf "${as_storepass}\n${as_storepass}\n${as_storepass}\n" |\
    keytool -importkeystore -srckeystore truststore -srcstoretype PKCS12 -destkeystore ${as_alias}_truststore -deststoretype JKS

    rm truststore

    cd ..
    #ac
    cd $ac_foldername

    printf "${ac_storepass}\n${ac_storepass}\nyes\n" |\
    keytool -import -alias $md_alias -file "../${md_foldername}/${md_cert}" -keystore truststore # MD

    printf "${ac_storepass}\nyes\n" |\
    keytool -import -alias $as_alias -file "../${as_foldername}/${as_cert}" -keystore truststore # AS

    printf "${ac_storepass}\nyes\n" |\
    keytool -import -alias $ss_alias -file "../${ss_foldername}/${ss_cert}" -keystore truststore # SS

    printf "${ac_storepass}\n${ac_storepass}\n${ac_storepass}\n" |\
    keytool -importkeystore -srckeystore truststore -srcstoretype PKCS12 -destkeystore ${ac_alias}_truststore -deststoretype JKS

    rm truststore

    cd ..
    #ss
    cd $ss_foldername

    printf "${ss_storepass}\n${ss_storepass}\nyes\n" |\
    keytool -import -alias $md_alias -file "../${md_foldername}/${md_cert}" -keystore truststore # MD

    printf "${ss_storepass}\nyes\n" |\
    keytool -import -alias $as_alias -file "../${as_foldername}/${as_cert}" -keystore truststore # AS

    printf "${ss_storepass}\nyes\n" |\
    keytool -import -alias $ac_alias -file "../${ac_foldername}/${ac_cert}" -keystore truststore # AC

    printf "${ss_storepass}\n${ss_storepass}\n${ss_storepass}\n" |\
    keytool -importkeystore -srckeystore truststore -srcstoretype PKCS12 -destkeystore ${ss_alias}_truststore -deststoretype JKS

    rm truststore

    cd ..
}

addAllToMainDispatcherTruststore(){
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

addAllSeversToClientTruststore(){
    # 1- alias, 2- folder, 3- storepass
    cd $2

    printf "${3}\n${3}\nyes\n" |\
    keytool -import -alias $md_alias -file "../../${md_foldername}/${md_cert}" -keystore truststore

    printf "${3}\nyes\n" |\
    keytool -import -alias $as_alias -file "../../${as_foldername}/${as_cert}" -keystore truststore

    printf "${3}\nyes\n" |\
    keytool -import -alias $ac_alias -file "../../${ac_foldername}/${ac_cert}" -keystore truststore

    printf "${3}\nyes\n" |\
    keytool -import -alias $ss_alias -file "../../${ss_foldername}/${ss_cert}" -keystore truststore

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
#sleep 1

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
#sleep 3

# Add to truststores
addAllToMainDispatcherTruststore

addAllServersToAllOtherServersTruststores

cd $cl_foldername
for client_name in "${clients_array[@]}"; do
    addAllSeversToClientTruststore "${client_name}_${cl_alias}" ${client_name}Crypto $cl_storepass
done
cd ..

# Finish
echo "Process Finished"