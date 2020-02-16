#!/bin/bash

if [ -z "$1" ]
  then
    OUT_DIR="store"
  else
    OUT_DIR=$1
fi

PRIVATE_AUTHENTICATION_TOKEN="private_authentication_token"
PUBLIC_AUTHENTICATION_TOKEN="public_authentication_token"

PRIVATE_REFRESH_TOKEN="private_refresh_token"
PUBLIC_REFRESH_TOKEN="public_refresh_token"

mkdir -p ${OUT_DIR}

openssl genrsa -out ${OUT_DIR}/${PRIVATE_AUTHENTICATION_TOKEN}.pem 2048
openssl rsa -in ${OUT_DIR}/${PRIVATE_AUTHENTICATION_TOKEN}.pem -outform PEM -pubout -out ${OUT_DIR}/${PUBLIC_AUTHENTICATION_TOKEN}.pem

openssl genrsa -out ${OUT_DIR}/${PRIVATE_REFRESH_TOKEN}.pem 2048
openssl rsa -in ${OUT_DIR}/${PRIVATE_REFRESH_TOKEN}.pem -outform PEM -pubout -out ${OUT_DIR}/${PUBLIC_REFRESH_TOKEN}.pem
