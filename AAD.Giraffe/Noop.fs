namespace AAD.Noop

open Giraffe
open Microsoft.AspNetCore.Http
open System.Threading.Tasks
open System.IdentityModel.Tokens.Jwt
open AAD

/// PartProtector implements no-op verification (it always succeeds) for PartProtector interface.
[<RequireQualifiedAccess>]
module PartProtector =
    /// Creates PartProtector instance.
    let mkNew token =
        { new PartProtector<'token> with 
            member _.Verify (getDemand: HttpContext -> Task<Demand>) 
                            (onSuccess: 'token -> HttpHandler) = 
                onSuccess token
                
            member _.VerifyWith (getDemand: HttpContext -> Task<Demand>) 
                                (onSuccess: 'token -> HttpHandler)
                                (onError: 'token option -> WWWAuthenticate -> HttpHandler) = 
                onSuccess token
        }

    let mkDefault () = JwtSecurityToken() |> mkNew
