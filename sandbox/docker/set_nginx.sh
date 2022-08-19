#!/bin/bash

#mkdir -p /etc/ssl/{certs,private}

#openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/nginx-selfsigned.key -out /etc/ssl/certs/nginx-selfsigned.crt -subj "/C=BR/ST=SP/L=SP/O=DJWTO/OU=DJWTO Department/CN=djwto.com"

mkdir -p /etc/nginx/certs
mkdir -p /etc/nginx/vhost.d

for domain in front.domain.com back.domain.com
do
  openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/certs/$domain.key -out /etc/nginx/certs/$domain.crt -subj "/C=BR/ST=SP/L=SP/O=DJWTO/OU=DJWTO Department/CN=$domain"
done

echo 'proxy_cookie_domain .example.com .domain.com;' \
 | tee /etc/nginx/vhost.d/back.domain.com_location /etc/nginx/vhost.d/front.domain.com_location

source /app/docker-entrypoint.sh
