Umbra
=====

Acts as a security shim between a webserver and the outside world.

## Configuration

Set up JSON configuration file at `config/config.json`. You may want to use
`config/sample_config.json` as a template.

## Building

	cd src
	make

## Usage

`./shim SHIM_PORT SERVER_PORT [ERROR_PAGE]`

SHIM_PORT is the port that the shim listens on externally.

SERVER_PORT is the port that the shim expects the HTTP server to be listening on.

ERROR_PAGE is an optional argument which may serve as the error page. If not provided, a default one will be used.

## Example Usage

    ./shim 8080 8000
