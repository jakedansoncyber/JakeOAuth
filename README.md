# Oauth2 OIDC spec server written by hand

This is an Oauth2 IDP written directly from the Oauth2 spec. The goal of this
isn't to be perfect or have every feature available. Really it's to learn golang + Oauth2 at the same time.

# Notes

There is a pair of asymmetric keys under /keys. This is intentional. Please never store real private keys in a non-secure
location, like GitHub.


# TODO

Lots of todos...looks like I need to re read the spec because it seems like the postman client wants to attach challenge
method and its own state instead of creating it on the IDP side. 