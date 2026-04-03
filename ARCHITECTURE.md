# Large mTLS Demo Architecture

## Purpose

This project demonstrates browser-to-edge mTLS for standard web sessions.

The goal is to show how a browser can automatically present a client
certificate, how an edge load balancer can validate that certificate, and
how a conventional web application can consume that identity without
requiring every backend service to understand X.509 directly.

This demo does **not** attempt to showcase service-to-service mTLS inside
the backend network.

## High-Level Topology

The demo consists of three containers:

1. **Load Balancer (LB)**
2. **Application**
3. **Signing Service**

Only the load balancer is exposed to the browser. The application and
signing service are on a trusted internal network and are reachable only
through the load balancer.

## Responsibilities

### Load Balancer

The load balancer is the TLS edge for the demo.

Its responsibilities are:

- Terminate TLS connections from the browser.
- Validate client certificates for protected application traffic.
- Route requests to the application or signing service.
- Strip any client-supplied identity headers.
- Inject trusted headers derived from the validated client certificate.

The LB is the only backend component that directly evaluates the client
certificate during a normal authenticated browsing session.

### Application

The application owns user-facing web behavior.

Its responsibilities are:

- Handle login and normal HTTP session management.
- Maintain user records and user access flags.
- Decide whether a user is allowed to enroll for a client certificate.
- Issue short-lived enrollment tokens for certificate requests.
- Authorize access to the site after the LB has authenticated the cert.

The application is the source of truth for whether a user may access the
site.

### Signing Service

The signing service owns CA operations.

Its responsibilities are:

- Accept certificate signing requests (CSRs).
- Validate short-lived enrollment tokens issued by the application.
- Ignore or overwrite identity claims supplied by the CSR.
- Write certificate identity fields from trusted token claims.
- Sign and return client certificates.

The CA private key should exist only in this service.

## Trust Model

This demo separates **authentication** from **authorization**.

- The **LB authenticates the certificate**.
- The **application authorizes the user**.

This means a client can present a cryptographically valid certificate and
still be denied access by the application if the mapped user is disabled
or otherwise unauthorized.

The backend network is treated as trusted for the purposes of this demo.
Traffic between the LB, application, and signing service uses HTTP rather
than backend mTLS. This is an intentional simplification to keep the demo
focused on browser-to-edge mTLS.

## Certificate Model

The signing service acts as the client CA. It signs browser client
certificates after the user has authenticated through the application and
received an enrollment token.

The certificate should contain a **stable internal user identifier** in a
field the application can consume reliably, such as SAN or another fixed
identity field.

The application should not rely on certificate fingerprint as the primary
user identifier:

- A fingerprint identifies a specific certificate, not the account.
- Reissued certificates will have different fingerprints.

The certificate fingerprint is still useful for:

- Audit logging
- Distinguishing multiple certs for the same user
- Device-level tracking

## Identity Propagation

After the LB validates a client certificate, it forwards trusted
certificate-derived headers to the application.

Typical forwarded values include:

- User identifier from the certificate
- Certificate fingerprint
- Certificate issuer
- Certificate verification result

The application must trust these headers **only** because it is reachable
only from the LB and the LB strips any conflicting client-supplied values
before forwarding.

## Enrollment Flow

The expected enrollment flow is:

1. The user signs in through the application using normal web
   authentication.
2. The application decides whether the account may enroll for a client
   certificate.
3. The application issues a short-lived enrollment token containing
   trusted claims, including the internal user identifier.
4. The browser submits a CSR and the enrollment token to the signing
   service through the LB.
5. The signing service validates the enrollment token.
6. The signing service ignores identity values requested by the CSR and
   writes certificate identity from trusted token claims.
7. The signing service signs and returns the client certificate.

This prevents a client from requesting a certificate for another user by
placing a different username or email in the CSR.

## Authenticated Browsing Flow

The expected authenticated browsing flow is:

1. The browser connects to the LB over TLS.
2. The browser automatically presents a client certificate.
3. The LB validates the certificate against the client CA.
4. The LB forwards trusted identity headers to the application.
5. The application maps the certificate identity to a user account.
6. The application checks user access flags and site authorization rules.
7. The application grants or denies access.

## Revocation and Access Removal

This demo does not maintain a list of currently valid certificates and
does not support certificate revocation as a primary control.

Instead:

- Certificates remain cryptographically valid until they expire.
- Access is granted or denied at the application level based on the user
  account bound to the certificate.

This leads to an important behavior:

- A valid certificate can complete the TLS handshake at the LB.
- The application can still deny access because the bound user is
  disabled, blocked, or otherwise unauthorized.

This is a deliberate design choice for the demo.

## Security Assumptions and Constraints

The demo relies on the following assumptions:

- Only the LB is directly reachable by the browser.
- The application and signing service are reachable only from the LB.
- The LB strips spoofed identity headers and re-adds trusted headers.
- The signing service does not trust identity values provided in the CSR.
- Certificate issuance happens only after normal user authentication.

Because certificate revocation is not modeled, the system should prefer
short-lived client certificates. This reduces risk if a client key is
compromised.

## Out of Scope

The following are intentionally out of scope for this demo:

- Service-to-service mTLS between backend containers
- Full PKI lifecycle management
- Certificate revocation lists (CRLs)
- Online certificate status protocol (OCSP)
- Distributed authorization across many backend services

These technologies are compatible with the architecture, but they are not
necessary to demonstrate browser-driven mTLS identity at the edge.

## Demo Behaviors to Showcase

The demo should make the following cases visible:

1. **Valid certificate + active user** -> access granted
2. **Valid certificate + disabled user** -> TLS succeeds, application
   denies access
3. **Invalid or untrusted certificate** -> TLS fails at the LB

These three cases clearly show the split between certificate
authentication at the edge and authorization in the application.
