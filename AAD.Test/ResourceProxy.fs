namespace AADTests

open System
open System.Net
open System.Net.Http
open Microsoft.Identity.Client
open AAD

type ProxyResult<'r> =
    | Success of 'r
    | AuthenticationError of exn
    | AuthorizationError of HttpStatusCode

module Async =
    let catchResult comp = 
        async {
            match! comp |> Async.Catch with
            | Choice1Of2 r -> return Success r
            | Choice2Of2 err -> return AuthenticationError err
        }

module ProxyResult =
    let bindAsync comp r =
        async {
            match r with
            | Success r -> return! comp r
            | AuthenticationError err -> return AuthenticationError err
            | AuthorizationError code -> return AuthorizationError code
        }    

/// Async Result-based proxy
type ResourceProxy =
    abstract provision: unit->Async<ProxyResult<unit>>
    abstract read: unit->Async<ProxyResult<string>>
    abstract write: unit->Async<ProxyResult<string>>
    abstract httpClient: HttpClient
    abstract address: Uri

module ResourceProxy =

    let internal mkNew (address:Uri) (httpClient:HttpClient) withHeaders =
        { new ResourceProxy with 
            member __.httpClient = httpClient
            member __.address = address
            member __.provision() = 
                async {
                    use r = new HttpRequestMessage(Method = HttpMethod.Head,
                                                   RequestUri = address)
                    withHeaders r.Headers
                    let! response = httpClient.SendAsync r |> Async.AwaitTask
                    if int response.StatusCode > 400 then
                        return AuthorizationError response.StatusCode
                    else 
                        return Success ()                    
                }
            member __.read() = 
                async {
                    use r = new HttpRequestMessage(Method = HttpMethod.Get,
                                                   RequestUri = address)
                    withHeaders r.Headers
                    let! response = httpClient.SendAsync r |> Async.AwaitTask
                    let! content = response.Content.ReadAsStringAsync()
                    if int response.StatusCode > 400 then
                        return AuthorizationError response.StatusCode
                    else
                        return Success content
                }
            member __.write() = 
                async {
                    use r = new HttpRequestMessage(Method = HttpMethod.Put,
                                                   RequestUri = address)
                    withHeaders r.Headers
                    let! response = httpClient.SendAsync r |> Async.AwaitTask
                    let! content = response.Content.ReadAsStringAsync()
                    if int response.StatusCode > 400 then
                        return AuthorizationError response.StatusCode
                    else
                        return Success content
                }
        }
    
    let mkDefault (address:Uri) (httpClient:HttpClient) =
        mkNew address httpClient ignore
        
    let authenticate =
        Dictionary.memoize (fun (scopes:seq<Scope>, clientId, Secret secret, authority: Uri) -> 
            let app = ConfidentialClientApplicationBuilder.Create(ClientId.toString clientId)
                        .WithClientSecret(secret)
                        .WithAuthority(authority)
                        .Build()
            fun (proxy:ResourceProxy) ->
                ProxyAuthenticator.ofConfidentialClient (HeaderSetter.bearerAuthorization >> mkNew proxy.address proxy.httpClient)
                                                        scopes
                                                        app
                |> Async.catchResult
        )
