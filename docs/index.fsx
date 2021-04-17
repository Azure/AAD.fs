(** AAD.fs
======================
The library implements core abstractions that can be used to authorize access to web APIs implemented in Giraffe or Suave with Azure Active Directory, as well as primitives to implement authorization for other servers.

Concepts
---------------
### Requesting Party
A user, a service principal (AD Enterprise Application) or a client (AD Application) acting on behalf of a user.

### Resource Server
Suave or Giraffe server hosting the HTTP endpoints.

### Roles and scopes
A role is a computed value based on the scope in the request for a token and returned by AD as a claim in the token.
It can be an AD Role (`role` claim), an AD Application role (`roles` claim) or a plain `scp` scope - all of them will be evaluated by default. 

### Authorization

![flow](content/flow.svg)

1. When building the application routes construct a `PartProtector`
1. By default well-known URI of the AD authority will be contacted
1. Retrieved the signing keys will be used later to verify tokens
1. Requesting party requests a token, for example using assigned [application roles](https://docs.microsoft.com/en-us/azure/architecture/multitenant-identity/app-roles)
1. Pass the resulting token along with the http request in `Authorization` header
1. Pass the call to `PartProtector.Verify` - a `WebPart` that implements the validation
1. `PartProtector` asks for demands given the context of the request
1. `Demand` is a recursive data stucture, a simple single value can be captured in a `Pattern`
1. `PartProtector` checks the token and if matches the claims to the demands
1. If successful passes the validated token along into the user's `WebPart`
1. If unsuccessful returns either auto-generated or user-specified `WebPart` for the error

</br>

For the Giraffe example walkthrough see the [sample](https://azure.github.io/AAD.fs/sample.html).

</br>
 
Contributing and copyright
--------------------------
The project is hosted on [GitHub][gh] where you can [report issues][issues], fork 
the project and submit pull requests. 

The library is available under MIT license, which allows modification and 
redistribution for both commercial and non-commercial purposes. For more information see the 
[License file][license] in the GitHub repository. 

  [content]: https://github.com/Azure/AAD.fs/tree/master/docs/content
  [gh]: https://github.com/Azure/AAD.fs
  [issues]: https://github.com/Azure/AAD.fs/issues
  [readme]: https://github.com/Azure/AAD.fs/blob/master/README.md
  [license]: https://github.com/Azure/AAD.fs/blob/master/LICENSE.md

*)


