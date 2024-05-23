namespace AAD

open System
open System.IdentityModel.Tokens.Jwt


[<RequireQualifiedAccess>]
module internal TokenCache =
    open System.Threading.Tasks
    open Microsoft.Extensions.Caching.Memory

    let mkNew options =
        let cache = new MemoryCache(options)
        let getOrAdd key (mkEntry: string -> Task<Result<JwtSecurityToken,_>>) =
            cache.GetOrCreateAsync(key, fun e -> backgroundTask {
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
module internal JwtSecurityTokenIntrospector =
    open System.Threading.Tasks
    open YoLo
    open Microsoft.IdentityModel.Tokens
    open Microsoft.IdentityModel.Protocols.OpenIdConnect

    let mkNew (getConfig: unit -> Awaitable<OpenIdConnectConfiguration>)
              (cache:string -> (string -> Task<_>) -> Task<_>)
              (audiences: #seq<Audience>) = 
        let handler = JwtSecurityTokenHandler()

        let local (jwtEncodedString: string) =
            backgroundTask {
                let mutable issuer = None
                try
                    let! oidcConfig = getConfig()
                    issuer <- Some oidcConfig.Issuer
                    let vparams = TokenValidationParameters
                                    (ValidIssuer = oidcConfig.Issuer,
                                     ValidAudiences = Seq.map Audience.toString audiences,
                                     IssuerSigningKeys = oidcConfig.SigningKeys)
                    let _,token = handler.ValidateToken(jwtEncodedString,vparams)
                    return Ok (token :?> JwtSecurityToken)
                with err ->
                    let wwwAuthenticate = 
                        match issuer with
                        | Some issuer ->
                            sprintf "Bearer realm=\"%s\", audience=\"%s\", error_description=\"%s\""
                                    issuer
                                    (audiences |> Seq.map Audience.toString |> String.concat ",")
                                    err.Message
                        | _ -> sprintf "Bearer error_description=\"Unable to retrieve OIDC configuration: %s\"" err.Message
                    return Error wwwAuthenticate
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

type ResourceOwner<'token> =
    abstract Validate : demand: Demand -> 
                        onSuccess: ('token -> unit) -> 
                        onUnauthorized: ('token option -> WWWAuthenticate -> unit) -> 
                        tokenString: TokenString -> 
                        Awaitable<unit>

[<RequireQualifiedAccess>]
module ResourceOwner =
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

    let mkNew (introspect: TokenString -> Awaitable<Result<'token,string>>)
              (validate: Demand -> 'token -> Result<'token,string>) =
        { new ResourceOwner<'token> with
            member __.Validate (demand: Demand)
                               (onSuccess: 'token -> unit)
                               (onUnauthorized: 'token option -> WWWAuthenticate -> unit)
                               (tokenString: TokenString) =
                awaitable {
                    let! introspected = introspect tokenString
                    let validated = introspected |> Result.bind (validate demand)

                    match validated, introspected with
                    | Ok t,_ -> onSuccess t
                    | Error err, Ok t -> 
                        onUnauthorized (Some t) (WWWAuthenticate err)
                    | Error err, _ -> 
                        onUnauthorized None (WWWAuthenticate err)
                }
        }

    let validate (splitChar: char) (claimsProjection: 'token -> #seq<string>) (demand: Demand) (t: 'token) = 
        let claims =
            claimsProjection t
            |> Seq.map (String.split splitChar)
        demand
        |> Demand.eval claims  
        |> function true -> Ok t | _ -> Error (sprintf "Demand not met: %A" demand)
