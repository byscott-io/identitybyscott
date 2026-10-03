# Security

This repository is published for transparency. The code here authenticates
people and issues tokens, so if you find a flaw we would rather hear it from you
than not.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private vulnerability
reporting on this repository (Security → Report a vulnerability), which opens a
private advisory visible only to the maintainer.

Useful things to include: what an attacker can do, the smallest steps that
demonstrate it, and the commit you looked at. A proof of concept helps but is
not required.

## Scope

In scope: authentication and token-issuance logic, realm isolation, the CORS
origin checks, key handling and the published JWK Set, and anything in this
repository that could let one application act as another or one realm reach into
another.

Out of scope: the deployment of this service, which is configured elsewhere, and
reports produced solely by automated scanners without a demonstrated impact.

## What this service is not

It is not packaged for reuse and is not intended to be imported or deployed by
anyone else. There is no support commitment, and no guarantee of API stability.
