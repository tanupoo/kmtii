IMPLEMENTATION
==============

## Notation

- C: Client
- P: Proxy Server
- CA
- R: Repository
- PEM

    base64 encoded ascii armor including newlines.

- SessionName

    e.g. b44b573412e6134e0f3bfa2f2fb26e1d4b2724bf1f9d4a1e1432018a9572f221

- ClientLocalAddress
- ClientWANAddress
- AccessURL
- AccessNAME

## HTTP error code

        | 400  | Bad Request                   | Section 6.5.1            |
        | 401  | Unauthorized                  | Section 3.1 of [RFC7235] |
        | 403  | Forbidden                     | Section 6.5.3            |
        | 404  | Not Found                     | Section 6.5.4            |

## Client to Proxy Server

At least, one of certificates of the trusted points
to authenticate Proxy Server must be given.
a long hex string is recommended for session_name.

    CSR:
        CN = <SessionName>
        SAN: IP = <ClientLocalAddress>

    POST https://proxy.example.com/csr
    POST https://192.168.0.1/csr
    Content-Type: application/json
    Accept: application/json
    
    {
        "csr": "<PEM>"
        "session_name": "<SessionName>"
    }

The response from Proxy Server to Client:

    200 OK
    Content-Type: application/json
    
    {
        "access_url": "<URLR>",
        "lead_time": <seconds>
    }

e.g.
URLR is like:

    https://repository.example.com/eyJzY29wZSI6WyJTVUJTQ1JJQkVSOjEwM

The length is not defined.

## Proxy Server to CA

At least, one of certificates of the trusted points
to authenticate CA must be given.

    POST https://ca.example.com/csr
    Content-Type: application/json
    
    {
        "csr": "<PEM>",
        "client_addr": "<ClientLocalAddress>",
        "wan_addr": "<ClientWANAddress>",
        "session_name": "<SessionName>",
        "access_url": "<AccessURL>"
    }

The response from CA to Proxy Server:

    200 OK

## CA to Repository

At least, one of certificates of the trusted points
to authenticate Repository must be given.

    CERT:
        SAN: IP = <ClientLocalAddress>
        SAN: IP = <ClientWANAddress>
        SAN: DNS = <AccessName>

    POST https://ra.example.com/cert
    Content-Type: application/json
    
    {
        "cert": "<PEM>"
        "client_addr": "<ClientLocalAddress>"
        "session_name": "<SessionName>",
        "access_url": "<AccessURL>"
    }

The response from Repository to CA:

    200 OK

## Client to Repository

At least, one of certificates of the trusted points
to authenticate Repository must be given.

    POST <AccessURL>
    Content-Type: application/json
    Accept: application/json
    
    {
        "session_name": "<SessionName>",
    }

When Client access to Repository,
Repository checks both client_addr, session_name.

The reponse from Repository to Client.

    200 OK
    Content-Type: application/json
    
    {
        "cert": "<PEM>"
        "session_name": "<SessionName>",
    }

