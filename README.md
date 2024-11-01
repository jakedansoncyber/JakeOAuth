# Oauth2 OIDC spec server written by hand

This is an Oauth2 IDP written directly from the Oauth2 spec. The goal of this
isn't to be perfect or have every feature available. Really it's to learn golang + Oauth2 at the same time.

Will also implement PKCE and OIDC on top of the Oauth2 spec.

# Notes

There is a pair of asymmetric keys under /keys. This is intentional. Please never store real private keys in a non-secure
location, like GitHub.


# TODO (not in order)

- [ ] Implicit Grant
- [ ] Resource Owner Password Credentials Grant (maybe)
- [ ] Client Credentials Grant
- [ ] Extensions Grant (maybe)
- [ ] Refresh tokens
- [ ] Make sure error responses are in line with what is defined
- [ ] Make sure the nuances of the documentation line up with what is actually being implemented
- [ ] Implement all security considerations.
  - [ ] Document and show why the security considerations are necessary to implement
- [ ] Implement OIDC
- [ ] Implement PKCE
  - [ ] Make sure to validate in code that the PKCE codes are generated within spec


# Lessons learned so far

The Oauth2 specification is not the end all - be all. It's one part of many, to a solution.

For example, in RFC 6749 section 10.3, it specifically states:
```
   This specification does not provide any methods for the resource
   server to ensure that an access token presented to it by a given
   client was issued to that client by the authorization server.
```

This means that, based on the OAuth2 spec, there is no definition to how to handle Authentication and Authorization from
an access token. In this exact case meaning: we can't verify that the token came from who it says it came from (token validation based on
the token signature for example).

# Specs read through for this

1. [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
2. [OpenID Connection Core 1.0 incorporating errata set 2](https://openid.net/specs/openid-connect-core-1_0.html)
3. [Proof Key for Code Exchange by Oauth Public Clients](https://datatracker.ietf.org/doc/html/rfc7636)