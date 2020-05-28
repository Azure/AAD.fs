namespace AAD.Noop


open Suave
open Suave.Operators
open AAD
open System.IdentityModel.Tokens.Jwt

/// PartProtector implements no-op verification (it always succeeds) for PartProtector interface.
[<RequireQualifiedAccess>]
module PartProtector =
    let token = JwtSecurityToken()
    /// Creates PartProtector instance.
    let mkNew () =
        { new PartProtector with 
            member __.Verify (getDemand: HttpContext -> Async<Demand>) 
                             (onSuccess: JwtSecurityToken -> WebPart) = 
                onSuccess token
                
            member __.VerifyWith (getDemand: HttpContext -> Async<Demand>) 
                                 (onSuccess: JwtSecurityToken -> WebPart)
                                 (onError: JwtSecurityToken option -> WWWAuthenticate -> WebPart) = 
                onSuccess token
        }
