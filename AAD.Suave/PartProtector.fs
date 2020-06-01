namespace AAD

open Suave
open Suave.Operators
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Protocols.OpenIdConnect

/// PartProtector is the interface for a stateful protector instance.
/// Use PartProtector module to create the instances implementing this interface.
type PartProtector =
    /// Wraps the verify call                
    abstract Verify: getDemand: (HttpContext -> Async<Demand>) -> 
                     onSuccess: (JwtSecurityToken -> WebPart) ->
                     WebPart
    /// Handling both success and error outcomes
    abstract VerifyWith: getDemand: (HttpContext -> Async<Demand>) -> 
                         onSuccess: (JwtSecurityToken -> WebPart) ->
                         onError: (JwtSecurityToken option -> WWWAuthenticate -> WebPart) ->
                         WebPart

/// PartProtector module for working with stateful instances of PartProtector interface.
[<RequireQualifiedAccess>]
module PartProtector =
    open System.Net.Http

    module internal ResultHandler =
        let mkNew onError onSuccess =
            let mutable result = ServerErrors.INTERNAL_ERROR "Shouldn't happen"
            let handleSuccess token = 
                result <- onSuccess token
            let handleMissing (token: _ option) (authenticate:WWWAuthenticate) =
                result <- onError token authenticate
            handleSuccess,handleMissing,fun ctx -> result ctx

        let mkDefault onSuccess =
            mkNew (fun _ (WWWAuthenticate authenticate) ->
                        RequestErrors.FORBIDDEN "Missing required claims"
                        >=> Writers.setHeader "WWW-Authenticate" authenticate)
                  onSuccess

    /// Creates PartProtector instance using the client credentials provided.
    let mkNew (introspect: TokenString -> Async<Result<JwtSecurityToken,string>>)
              (validate: Demand -> JwtSecurityToken -> Result<JwtSecurityToken,string>)
              (audiences: #seq<Audience>)
              (oidcConfig: OpenIdConnectConfiguration) =
        let resourceOwner =
            ResourceOwner.mkNew introspect
                                validate
                                audiences
                                oidcConfig
                                                      
        { new PartProtector with 
            member __.Verify (getDemand: HttpContext -> Async<Demand>) 
                             (onSuccess: JwtSecurityToken -> WebPart) = 
                fun (ctx:HttpContext) ->
                    async {
                        let handleSuccess,handleMissing,result =
                            ResultHandler.mkDefault onSuccess
                        let! claims = getDemand ctx
                        do! resourceOwner.Validate claims
                                                   handleSuccess
                                                   handleMissing
                                                   (Readers.bearerTokenString ctx)
                        return! result ctx
                    }
            member __.VerifyWith (getDemand: HttpContext -> Async<Demand>) 
                                 (onSuccess: JwtSecurityToken -> WebPart)
                                 (onError: JwtSecurityToken option -> WWWAuthenticate -> WebPart) = 
                fun (ctx:HttpContext) ->
                    async {
                        let handleSuccess,handleMissing,result =
                            ResultHandler.mkNew onError onSuccess
                        let! claims = getDemand ctx
                        do! resourceOwner.Validate claims
                                                   handleSuccess
                                                   handleMissing
                                                   (Readers.bearerTokenString ctx)
                        return! result ctx
                    }
        }

    /// Default constructor with roles, appRoles and scopes filter and `/` separator
    let mkDefault (httpClient: HttpClient)
                  (audiences: #seq<Audience>)
                  (authority: System.Uri) =
        async {
            let! conf = OpenIdConnectConfigurationRetriever
                            .GetAsync(sprintf "%O/.well-known/openid-configuration" authority, httpClient, System.Threading.CancellationToken.None)
                        |> Async.AwaitTask                        
        
            let introspect = 
                (TokenCache.mkDefault(), audiences, conf) |||> Introspector.mkNew 
            let inline filter claim =
                ResourceOwner.ClaimFilters.isAppRole claim
                || ResourceOwner.ClaimFilters.isRole claim
                || ResourceOwner.ClaimFilters.isScope claim
            
            return mkNew introspect
                         (ResourceOwner.validate '/' filter) 
                         audiences
                         conf
        }