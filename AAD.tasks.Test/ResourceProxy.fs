namespace AADTests

open System
open System.Threading.Tasks
open System.Net.Http
open AAD
open Microsoft.Identity.Client

/// An NSwag-like service proxy
type ResourceProxy =
    abstract provision: unit->Task
    abstract read: unit->Task<string>
    abstract write: unit->Task<string>
    abstract httpClient: HttpClient
    abstract address: Uri

type ProxyException(status) = 
    inherit exn()
    member __.Denied = status = System.Net.HttpStatusCode.Forbidden

module ResourceProxy =

    let internal mkNew (address:Uri) (httpClient:HttpClient) withHeaders =
        { new ResourceProxy with 
            member __.httpClient = httpClient
            member __.address = address
            member __.provision() = 
                backgroundTask {
                    use r = new HttpRequestMessage(Method = HttpMethod.Head,
                                                   RequestUri = address)
                    withHeaders r.Headers
                    let! response = httpClient.SendAsync r
                    if int response.StatusCode > 400 then
                        raise (ProxyException response.StatusCode)
                } :> Task
            member __.read() = 
                backgroundTask {
                    use r = new HttpRequestMessage(Method = HttpMethod.Get,
                                                   RequestUri = address)
                    withHeaders r.Headers
                    let! response = httpClient.SendAsync r
                    let! content = response.Content.ReadAsStringAsync()
                    if int response.StatusCode > 400 then
                        raise (ProxyException response.StatusCode)
                    return content
                }
            member __.write() = 
                backgroundTask {
                    use r = new HttpRequestMessage(Method = HttpMethod.Put,
                                                   RequestUri = address)
                    withHeaders r.Headers
                    let! response = httpClient.SendAsync r
                    let! content = response.Content.ReadAsStringAsync()
                    if int response.StatusCode > 400 then
                        raise (ProxyException response.StatusCode)
                    return content
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
        )
