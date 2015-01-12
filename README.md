Umbra
=====

Acts as a security shim between a webserver and the outside world.

## Requirements

Requires gcc, make, python2.7, and check (for unit tests)

These can be installed on Ubuntu with:

```
sudo apt-get install build-essential check python
```

## Configuration

Set up JSON configuration file at `config/config.json`. You may want to use
`config/sample_config.json` as a template.

## Building

    cd src
    make

## Usage

    Usage: ./shim-trace <REQUIRED ARGUMENTS> [OPTIONAL ARGUMENTS]

    Required arguments:
    --shim-http-port      HTTP port on which shim should listen
    --server-http-port    port of listening HTTP server
    --shim-tls-port       HTTPS port on which shim should listen
    --server-tls-port     port of listening HTTPS server
    --tls-cert            PEM file with TLS certificate chain
    --tls-key             PEM file with server private key

    Optional arguments:
    --error-page          file containing contents for error page
    --server-host         IP address or hostname of webserver. Defaults to localhost.
    --print-config        Print compiled in configuration data


## Example Usage

    ./shim --shim-http-port 8080 --server-http-port 8000 \
        --shim-tls-port 8443 --server-tls-port 4430 \
        --tls-cert server.crt.pem --tls-key server.key.pem
