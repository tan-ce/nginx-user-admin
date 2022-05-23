# nginx-user-admin

nginx-user-admin is a simple PHP application that implements a backend that is meant to be used with NGINX's subrequest based HTTP authentication. ([See documentation here.](https://nginx.org/en/docs/http/ngx_http_auth_request_module.html))

There is also a frontend that can be used to manage users. Users are created through invite links. There is basic privilege separation based on groups is implemented. The user database is stored in an SQLite database, with passwords hashed using PHP's `password_hash()`.

## Prerequisites

A web server and PHP  7.x is required. The instructions and examples below assume you are using NGINX throughout.

## Setup and Installation

The following applies to the examples below:
* The repository was cloned to `/var/www/auth`.
* The admin front end is made available at the URL `/admin`.
* A php-fpm server is running at the address `php:9000`.
* The authentication endpoint is made available at the URL `/auth`.

### Config and Admin Frontend

1. Clone the repository.
```
git clone https://github.com/tan-ce/nginx-user-admin.git auth
```
2. Copy the sample config file, and edit it for your use.
```
cd auth
cp config.sample.inc.php config.inc.php
```
3. Set up access to the admin frontend. All requests should be routed to `admin.php`. In the NGINX configuration example below:
```
    location /admin {
        fastcgi_pass php:9000;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/auth/admin.php;
    }

    location /admin/res {
        alias /var/www/auth/res;
        try_files $uri =404;
    }
```
4. Ensure that DB_PATH (both the file and directory) is writeable by the PHP interpreter.
5. Configure either a local authentication endpoint or a remote authentication endpoint. (See below.)

### Authentication Syntax
Several examples for different kinds of authentication requirements are shown below.
```
# Any user in the database can access this location
location /anyone {
    auth_request /auth/any/any;
    ...
}

# Any user in the group "foogroup" can access this location
location /group {
    auth_request /auth/group/foogroup;
    ...
}

# Only the user "foouser" can access this location
location /user-private {
    auth_request /auth/user/foouser;
    ...
}
```

### Authentication endpoint (local only)

This example configuration makes subrequest authentication available only to the same NGINX server that is hosting nginx-user-admin.
```
    location /auth {
        internal;
        fastcgi_pass php:9000;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/auth/index.php;
    }
```
### Authentication endpoint (remote)

This example configuration makes subrequest and JSON based authentication available to other NGINX servers on the network. Because the login credentials are sent in the clear (using HTTP Basic Authentication), server-to-server connections must be encrypted. These examples will use TLS for this purpose with both client and server authentication.

This example requires the following certificates and keys:

* Certificate Authority (CA) - `ca.crt`
* Server (the NGINX server running nginx-user-admin)
    * TLS Server Certificate - `server.pem`
    * Private Key - `server.key.pem`
* Client (the NGINX server presenting authentication to the user)
    * TLS Client Certificate - `client.pem`
    * Private Key - `client.key.pem`

These certificates and keys can be generated using something like `easy-rsa` or [`mkcert`](https://github.com/FiloSottile/mkcert)

Server configuration:
```
server {
    listen 443 ssl;
    server_name auth.example.com;

    ssl_certificate_key /etc/nginx/keys/server.key.pem;
    ssl_certificate /etc/nginx/keys/server.pem;
    ssl_trusted_certificate /etc/nginx/keys/ca.crt;
    ssl_client_certificate /etc/nginx/keys/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # Adjust as necessary
    ssl_session_cache shared:SSL:10m;
    keepalive_timeout 10;
    ssl_session_timeout 10m;

    ssl_protocols TLSv1.3;
    ssl_ciphers TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-256-GCM-SHA384:TLS13-AES-128-GCM-SHA256:EECDH+CHACHA20:EECDH+AESGCM:EECDH+AES;
    ssl_ecdh_curve secp384r1;

    location /auth {
        fastcgi_pass php:9000;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/auth/index.php;
    }

    location /auth-json {
        fastcgi_pass php:9000;
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/auth/json.php;
    }
}
```
Client configuration (only location blocks shown):
```
    location /auth {
        internal;
        proxy_pass              https://auth.example.com/auth;
        proxy_pass_request_body off;
        proxy_set_header        Content-Length "";
        proxy_set_header        X-Original-URI $request_uri;
        proxy_ssl_certificate           /etc/nginx/keys/client.pem;
        proxy_ssl_certificate_key       /etc/nginx/keys/client.key.pem;
        proxy_ssl_trusted_certificate   /etc/nginx/keys/ca.crt;
        proxy_ssl_verify_depth          2;
        proxy_ssl_session_reuse         on;
        proxy_ssl_protocols             TLSv1.3;
    }
```
