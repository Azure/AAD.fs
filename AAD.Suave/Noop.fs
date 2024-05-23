namespace AAD.Noop


open Suave
open AAD
open System.IdentityModel.Tokens.Jwt

/// PartProtector implements no-op verification (it always succeeds) for PartProtector interface.
[<RequireQualifiedAccess>]
module PartProtector =
    /// Creates PartProtector instance.
    let mkNew token =
        { new PartProtector<'token> with 
            member __.Verify (getDemand: HttpContext -> Async<Demand>) 
                             (onSuccess: 'token -> WebPart) = 
                onSuccess token
                
            member __.VerifyWith (getDemand: HttpContext -> Async<Demand>) 
                                 (onSuccess: 'token -> WebPart)
                                 (onError: 'token option -> WWWAuthenticate -> WebPart) = 
                onSuccess token
        }

    let mkDefault () = JwtSecurityToken()