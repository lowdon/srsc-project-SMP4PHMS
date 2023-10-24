#! /bin/bash

rm keystore/bob.jks
rm keystore/jeff.jks

keytool -genkey -alias bob -keyalg DSA -keystore bob.jks -keysize 2048 -storepass password -storetype JKS
keytool -genkey -alias jeff -keyalg DSA -keystore jeff.jks -keysize 2048 -storepass password -storetype JKS

mv jeff.jks ./keystore/
mv bob.jks ./keystore/
