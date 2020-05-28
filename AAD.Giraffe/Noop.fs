namespace AAD.Noop

open Giraffe
open Microsoft.AspNetCore.Http
open System.Threading.Tasks
open System.IdentityModel.Tokens.Jwt
open AAD

/// PartProtector implements no-op verification (it always succeeds) for PartProtector interface.
[<RequireQualifiedAccess>]
module PartProtector =
    let token = JwtSecurityToken()
    /// Creates PartProtector instance.
    let mkNew () =
        { new PartProtector with 
            member __.Verify (getDemand: HttpContext -> Task<Demand>) 
                             (onSuccess: JwtSecurityToken -> HttpHandler) = 
                onSuccess token
                
            member __.VerifyWith (getDemand: HttpContext -> Task<Demand>) 
                                 (onSuccess: JwtSecurityToken -> HttpHandler)
                                 (onError: JwtSecurityToken option -> WWWAuthenticate -> HttpHandler) = 
                onSuccess token
        }
