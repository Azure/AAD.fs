namespace AAD

open Suave
open Suave.Operators
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Protocols.OpenIdConnect
open Microsoft.Extensions.Caching.Memory

/// PartProtector is the interface for a stateful protector instance.
/// Use PartProtector module to create the instances implementing this interface.
type PartProtector<'token> =
    /// Wraps the verify call                
    abstract Verify: getDemand: (HttpContext -> Async<Demand>) -> 
                     onSuccess: ('token -> WebPart) ->
                     WebPart
    /// Handling both success and error outcomes
    abstract VerifyWith: getDemand: (HttpContext -> Async<Demand>) -> 
                         onSuccess: ('token -> WebPart) ->
                         onError: ('token option -> WWWAuthenticate -> WebPart) ->
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
                        RequestErrors.FORBIDDEN ""
                        >=> Writers.setHeader "WWW-Authenticate" authenticate)
                  onSuccess

    /// Creates PartProtector instance using the client credentials provided.
    let mkNew (introspect: TokenString -> Async<Result<'token,string>>)
              (validate: Demand -> 'token -> Result<'token,string>) =
        let resourceOwner =
            ResourceOwner.mkNew introspect validate
                                                      
        { new PartProtector<'token> with 
            member __.Verify (getDemand: HttpContext -> Async<Demand>) 
                             (onSuccess: 'token -> WebPart) = 
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
                                 (onSuccess: 'token -> WebPart)
                                 (onError: 'token option -> WWWAuthenticate -> WebPart) = 
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
            let getConfiguration =
                let cache = new MemoryCache(new MemoryCacheOptions(SizeLimit = 1L)) 
                fun () -> 
                    cache.GetOrCreateAsync(1, fun e -> backgroundTask {
                        let! r = OpenIdConnectConfigurationRetriever
                                    .GetAsync(sprintf "%O/.well-known/openid-configuration" authority, httpClient, System.Threading.CancellationToken.None)
                                    .ConfigureAwait false
                        e.SetAbsoluteExpiration (System.TimeSpan.FromHours 24.) |> ignore
                        e.SetSize 1L |> ignore
                        return r
                    }) |> Async.AwaitTask
        
            let! _ = getConfiguration() // prime the config cache
            let introspect = 
                (TokenCache.mkDefault(), audiences) ||> JwtSecurityTokenIntrospector.mkNew getConfiguration
            let project (token: JwtSecurityToken) =
                token.Claims
                |> Seq.collect (fun claim ->
                    seq {
                        yield! ResourceOwner.ClaimProjection.ofAppRole claim
                        yield! ResourceOwner.ClaimProjection.ofRole claim
                        yield! ResourceOwner.ClaimProjection.ofScope claim
                    }
                )
            return mkNew introspect
                         (ResourceOwner.validate '/' project) 
        }