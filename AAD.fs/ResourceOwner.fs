namespace AAD

open System
open System.IdentityModel.Tokens.Jwt


[<RequireQualifiedAccess>]
module internal TokenCache =
    open System.Threading.Tasks
    open Microsoft.Extensions.Caching.Memory
    open FSharp.Control.Tasks

    let mkNew options =
        let cache = new MemoryCache(options)
        let getOrAdd key (mkEntry: string -> Task<Result<JwtSecurityToken,_>>) =
            cache.GetOrCreateAsync(key, fun e -> task {
                let! r = mkEntry key
                match r with
                | Ok entry ->
                    e.SetAbsoluteExpiration (DateTimeOffset entry.ValidTo) |> ignore
                | _ -> 
                    e.SetSlidingExpiration (TimeSpan.FromMinutes 1.) |> ignore
                    e.SetPriority CacheItemPriority.Low |> ignore
                e.SetSize 1L |> ignore                                            
                return r
            })
        getOrAdd
        
    let mkDefault () =
        MemoryCacheOptions(CompactionPercentage = 0.10, SizeLimit = Nullable 100L)
        |> mkNew


[<RequireQualifiedAccess>]
module internal Introspector =
    open System.Threading.Tasks
    open YoLo
    open Microsoft.IdentityModel.Tokens
    open Microsoft.IdentityModel.Protocols.OpenIdConnect
    open FSharp.Control.Tasks.V2.ContextInsensitive

    let mkNew (cache:string -> (string -> Task<_>) -> Task<_>)
              (audiences: #seq<Audience>)
              (getConfig: unit -> Awaitable<OpenIdConnectConfiguration>) = 
        let handler = JwtSecurityTokenHandler()

        let local (jwtEncodedString: string) =
            task {
                try
                    let! oidcConfig = getConfig()
                    let vparams = TokenValidationParameters
                                    (ValidIssuer = oidcConfig.Issuer,
                                     ValidAudiences = Seq.map Audience.toString audiences,
                                     IssuerSigningKeys = oidcConfig.SigningKeys)
                    let _,token = handler.ValidateToken(jwtEncodedString,vparams)
                    return Ok (token :?> JwtSecurityToken)
                with err ->
                    return Error err.Message
            }
                
        let parse s =
            s
            |> String.split '.'
            |> function | [_;_;_] -> local s
                        | [""] -> Error "No token" |> Task.FromResult
                        | _ -> Error "Unsupported token" |> Task.FromResult
                
        fun (TokenString s) ->
            awaitable {
                let! r = cache s parse
                return r
            }

type ResourceOwner =
    abstract Validate : demand: Demand -> 
                        onSuccess: (JwtSecurityToken -> unit) -> 
                        onUnauthorized: (JwtSecurityToken option -> WWWAuthenticate -> unit) -> 
                        tokenString: TokenString -> 
                        Awaitable<unit>

[<RequireQualifiedAccess>]
module ResourceOwner =
    open Microsoft.IdentityModel.Protocols.OpenIdConnect
    open System.Security.Claims
    
    module ClaimProjection = 
        let ofScope (claim: Claim) : seq<string> =
            if claim.Type = "scp" then claim.Value |> String.split ' ' :> _
            else Seq.empty 

        let ofRole (claim: Claim) : seq<string> =
            if claim.Type = "role" then Seq.singleton claim.Value
            else Seq.empty

        let ofAppRole (claim: Claim) : seq<string> =
            if claim.Type = "roles" then Seq.singleton claim.Value
            else Seq.empty

    let mkNew (introspect: TokenString -> Awaitable<Result<JwtSecurityToken,string>>)
              (validate: Demand -> JwtSecurityToken -> Result<JwtSecurityToken,string>)
              (audiences: #seq<Audience>)
              (getConfig: unit -> Awaitable<OpenIdConnectConfiguration>) =
        { new ResourceOwner with
            member __.Validate (demand: Demand)
                               (onSuccess: JwtSecurityToken -> unit)
                               (onUnauthorized: JwtSecurityToken option -> WWWAuthenticate -> unit)
                               (tokenString: TokenString) =
                awaitable {
                    let! oidcConfig = getConfig()
                    let! introspected = introspect tokenString
                    let validated = introspected |> Result.bind (validate demand)

                    let wwwAuthenticate err = 
                            sprintf "Bearer realm=\"%s\", audience=\"%A\", error_description=\"%s\""
                                    oidcConfig.Issuer
                                    (audiences |> Seq.map Audience.toString |> String.concat ",")
                                    err
                    match validated, introspected with
                    | Ok t,_ -> onSuccess t
                    | Error err, Ok t -> 
                        onUnauthorized (Some t) (wwwAuthenticate err |> WWWAuthenticate)
                    | Error err, _ -> 
                        onUnauthorized None (wwwAuthenticate err |> WWWAuthenticate)
                }
        }

    let validate (splitChar: char) (claimsProjection: Claim -> #seq<string>) (demand: Demand) (t: JwtSecurityToken) = 
        let claims =
            t.Claims
            |> Seq.collect claimsProjection
            |> Seq.map (String.split splitChar)
        demand
        |> Demand.eval claims  
        |> function true -> Ok t | _ -> Error (sprintf "Demand not met: %A" demand)
