namespace AAD

open Microsoft.AspNetCore.Http
open System.Threading.Tasks
open Giraffe
open FSharp.Control.Tasks.V2.ContextInsensitive
open System.IdentityModel.Tokens.Jwt
open Microsoft.IdentityModel.Protocols.OpenIdConnect
open Microsoft.Extensions.Caching.Memory

/// PartProtector is the interface for a stateful protector instance.
/// Use PartProtector module to create the instances implementing this interface.
type PartProtector =
    /// Wraps the verify call                
    abstract Verify: getDemand: (HttpContext -> Task<Demand>) -> 
                     onSuccess: (JwtSecurityToken -> HttpHandler) -> 
                     HttpHandler
    /// Handling both success and error outcomes
    abstract VerifyWith: getDemand: (HttpContext -> Task<Demand>) -> 
                         onSuccess: (JwtSecurityToken -> HttpHandler) -> 
                         onError: (JwtSecurityToken option -> WWWAuthenticate -> HttpHandler) -> 
                         HttpHandler

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
                        Writers.setWWWAuthenticate authenticate
                        >=> Writers.forbidden "Missing required demand")
                  onSuccess

    /// Creates PartProtector instance using the client credentials provided.
    let mkNew (introspect: TokenString -> Task<Result<JwtSecurityToken,string>>)
              (validate: Demand -> JwtSecurityToken -> Result<JwtSecurityToken,string>)
              (audiences: #seq<Audience>)
              (getConfig: unit -> Task<OpenIdConnectConfiguration>) =
        let resourceOwner =
            ResourceOwner.mkNew introspect validate audiences getConfig
                                                      
        { new PartProtector with 
            member __.Verify (getDemand: HttpContext -> Task<Demand>) 
                             (onSuccess: JwtSecurityToken -> HttpHandler) = 
                fun next (ctx:HttpContext) -> 
                    task {
                        let handleSuccess,handleMissing,result =
                            ResultHandler.mkDefault onSuccess
                        let! demand = getDemand ctx
                        do! resourceOwner.Validate demand
                                                   handleSuccess
                                                   handleMissing
                                                   (Readers.bearerTokenString ctx)
                        return! result next ctx
                    }
            member __.VerifyWith (getDemand: HttpContext -> Task<Demand>) 
                                 (onSuccess: JwtSecurityToken -> HttpHandler)
                                 (onError: JwtSecurityToken option -> WWWAuthenticate -> HttpHandler) = 
                fun next (ctx:HttpContext) -> 
                    task {
                        let handleSuccess,handleMissing,result =
                            ResultHandler.mkNew onError onSuccess
                        let! demand = getDemand ctx
                        do! resourceOwner.Validate demand
                                                   handleSuccess
                                                   handleMissing
                                                   (Readers.bearerTokenString ctx)
                        return! result next ctx
                    }
        }
    
    
    /// Default constructor with roles, appRoles and scopes filter and `/` separator
    let mkDefault (httpClient: HttpClient)
                  (audiences: #seq<Audience>)
                  (authority: System.Uri) =
        task {
            let getConfiguration =
                let cache = new MemoryCache(new MemoryCacheOptions(SizeLimit = 1L)) 
                fun () -> cache.GetOrCreateAsync(1, fun e -> task {
                    let! r = OpenIdConnectConfigurationRetriever
                                .GetAsync(sprintf "%O/.well-known/openid-configuration" authority, httpClient, System.Threading.CancellationToken.None)
                                .ConfigureAwait false
                    e.SetAbsoluteExpiration (System.TimeSpan.FromHours 24.) |> ignore
                    e.SetSize 1L |> ignore
                    return r
                })
        
            let introspect = 
                (TokenCache.mkDefault(), audiences, getConfiguration) |||> Introspector.mkNew 
            let project claim =
                seq {
                    yield! ResourceOwner.ClaimProjection.ofAppRole claim
                    yield! ResourceOwner.ClaimProjection.ofRole claim
                    yield! ResourceOwner.ClaimProjection.ofScope claim
                }
            
            return mkNew introspect
                         (ResourceOwner.validate '/' project) 
                         audiences
                         getConfiguration
        }