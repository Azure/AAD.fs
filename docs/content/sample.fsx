(*** hide ***)
#I "../../AAD.tasks.Test/bin/Debug/netcoreapp3.0"
#r "TaskBuilder.fs.dll"
#r "AAD.Giraffe.dll"
#r "AAD.fs.tasks.dll"
#r "Giraffe.dll"
open System
open FSharp.Control.Tasks
open Giraffe
open AAD
let httpClient = new Net.Http.HttpClient()
let audience = [""]
let authority = Uri("")

(** The sample
---------
The example implements authorization using [Azure Application Roles](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps). The sample application can be found in your Azure Active Directory once provisioned:

- `dotnet fake build -t registerSample`

For simplicity, the sample uses service principals as identities for the Requesting Party. The registration creates following items in the AD:

- `aad-sample-admin` service principal (Requesting Party) 
- `aad-sample-reader` service principal (Requesting Party)
- `aad-sample-writer` service principal (Requesting Party)
- `aad-fs-sample` application (Resource Server) and corresponging Enterprise Application to manage application role assignments 

> Note: All the identitifiers will have a random suffix added.

`aad-sample` will have following AppRoles defined:

- `Admin` with `*/*` value
- `Reader` with `items/r` value
- `Writer` with `items/w` value

Once provisioned you can find these roles in the application's manifest, it will look something like this:

![appRoles](img/manifest_roles.png)


Requesting Party service principals will have the corresponding roles assigned, which you can check in the Enterprise Application's `Users and Groups` blade:

![assignments](img/assignments.png)


Authoring the roles
---------
The role values can be anything you need. The example here demonstrates the capability of the library to deal with patterns and wildcards:

A "pattern" means that we can expect a structure in the value, like "items/r" or "items.r" - `/` is the default separator, but the character is configurable - use `PartProtector.mkNew` instead of `mkDefault` if you need to change it.
Use `*` wildcard in any segment of the role value to make any demand match that part of the pattern, for example `items/*` in the role value will match the demands like `items/r`, `items/w`, etc.
`*/*` means that the identity with that claim in the token will have access to APIs that demand `items`, `fiddles/play`, `cats/herd`, etc with or w/o any 2nd (verb) segment.

Complex demands can be expressed by combining the patterns with `Any` and `All`, for example:

- `All [Pattern ["A";"1"]; Pattern ["B";"2"]]` will only match if both `A/1` and `B/2` are present among the token claims. 
*)


(** Implementing Resource Server
---------
The full source code for this sample is in `AAD.tasks.Test/ResourceServers.fs`, but here are the important ingredients:
*)

task {
    let! protector : PartProtector = 
        PartProtector.mkDefault httpClient audience authority
        
    let read : HttpHandler =
        protector.Verify (fun ctx -> Task.FromResult <| Pattern ["items"; "r"])
                         (fun token -> text "Read!")

    let write : HttpHandler =
        protector.Verify (fun ctx -> Task.FromResult <| Pattern ["items"; "w"])
                         (fun token -> text "Written!")
        
    return 
        choose [
          HEAD >=> route "/" >=> Successful.NO_CONTENT
          GET >=> route "/" >=> read
          PUT >=> route "/" >=> write
          RequestErrors.NOT_FOUND ""
        ]
}

(** 
As you can see:

- all the tokens that `protector` handles are issued for a specific `audience` - our `aad-fs-sample` 
- the functions that return the demands for a given handler are asynchronous to facilitate potential IO based on the context of the request.
- `read` HttpHandler demands access with a token that has a claim in one of [`role`, `roles` or `scp`] that matches the pattern `items/r` 
- `write` HttpHandler demands access with a token that has a claim that matches the pattern `items/w`

And as mentioned above, `Admin` with its `*/*` value will meet both of those demands.
*)


(** Requesting the token
---------
On the Requesting Party side, we need to tell the AD that we need the appRoles assigned to our principals mapped to the token claims.
We do that by specifying our `Application URI` as a scope, in case of the registerd sample it will look something like: `api://{clientid}/.default`, where the `/.default` suffix is a special identifier that tells AD to figure which role(s) the user has in the application instead of requesting one specific role. 
The samples use [MSAL](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet) to obtain and refresh the token as needed.
*)


(** Passing the token with a call
---------
Considering that the token is refreshed periodically, `AsyncRequestor` or `TaskRequestor` can be useful to ensure a token is obtained and associated it with each request.   
*)
