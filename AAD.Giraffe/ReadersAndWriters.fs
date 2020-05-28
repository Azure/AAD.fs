namespace AAD
open Giraffe

module Readers =
    open Microsoft.AspNetCore.Http
    open AAD.Domain

    let bearer (ctx: HttpContext) =
        ctx.TryGetRequestHeader "Authorization"
        |> Option.map (String.split ' ') 
        |> Option.bind (function ["Bearer"; token] -> Some token | _ -> None)

    let bearerTokenString : HttpContext -> TokenString =
        bearer >> Option.map TokenString >> Option.defaultValue (TokenString "") 

module Writers =
    let inline setMimeType mimeType: HttpHandler =
        setHttpHeader "Content-Type" mimeType 
        
    let inline setWWWAuthenticate value: HttpHandler =
        setHttpHeader "WWW-Authenticate" value 

    let unauthorized body: HttpHandler =
        setStatusCode 401 >=> setBodyFromString body 
    
    let forbidden body: HttpHandler =
        setStatusCode 403 >=> setBodyFromString body