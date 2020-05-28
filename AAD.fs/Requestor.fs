namespace AAD

open System
open Microsoft.Identity.Client

/// Requestor interface for transparent authentication of task-based proxies.
type TaskRequestor<'proxy> =
    /// Call a task that returns a value.
    abstract member Call<'r> : ('proxy -> Threading.Tasks.Task<'r>) -> Awaitable<'r>
    /// Call a task that doesn't return anything.
    abstract member Do : ('proxy -> Threading.Tasks.Task) -> Awaitable<unit>

/// Requestor interface for transparent authentication of async-based clients.
type AsyncRequestor<'proxy> =
    /// Call an async function that returns a value.
    abstract member Call<'r> : ('proxy -> Async<'r>) -> Awaitable<'r>
    /// Call an async function that doesn't return anything.
    abstract member Do : ('proxy -> Async<unit>) -> Awaitable<unit>

/// Requestor for task-based proxies.
[<RequireQualifiedAccess>]
module TaskRequestor =
    
    /// Creates new instance of a Task requestor.
    let mkNew (mkAuthenticated: 'arg -> Threading.Tasks.Task<'proxy>)
              (arg: 'arg) =
        { new TaskRequestor<'proxy> with 
            member __.Call(call: 'proxy -> Threading.Tasks.Task<'r>) =
                awaitable {
                    let! proxy = mkAuthenticated arg |> Awaitable.awaitTask
                    return! call proxy |> Awaitable.awaitTask
                }
                
            member __.Do(call: 'proxy -> Threading.Tasks.Task) =
                awaitable {
                    let! proxy = mkAuthenticated arg |> Awaitable.awaitTask
                    return! call proxy |> Awaitable.awaitUnitTask
                }
        }

/// Requestor for async-based proxies.
[<RequireQualifiedAccess>]
module AsyncRequestor =
    /// Creates new instance of an Async requestor.
    let mkNew (mkAuthenticated: 'arg -> Async<'proxy>)
              (arg: 'arg) =
        { new AsyncRequestor<'proxy> with 
            member __.Call(call: 'proxy -> Async<'r>) =
                awaitable {
                    let! proxy = mkAuthenticated arg |> Awaitable.awaitAsync
                    return! call proxy |> Awaitable.awaitAsync
                }
                
            member __.Do(call: 'proxy -> Async<unit>) =
                awaitable {
                    let! proxy = mkAuthenticated arg |> Awaitable.awaitAsync
                    return! call proxy |> Awaitable.awaitAsync
                }
        }

/// Authenticator uses MSAL to obtain a token and create a proxy with it 
[<RequireQualifiedAccess>]
module ProxyAuthenticator =
    let ofConfidentialClient (mkAuthenticated: TokenString -> 'proxy)
                             (scopes: #seq<Scope>)
                             (clientApp: IConfidentialClientApplication) =
        awaitable {
            let! token =
                (scopes |> Seq.map Scope.toString |> clientApp.AcquireTokenForClient).ExecuteAsync()
                |> Awaitable.awaitTask
            return mkAuthenticated (TokenString token.AccessToken)
        }

/// Helpers to set request headers
[<RequireQualifiedAccess>]
module HeaderSetter =
    open System.Net.Http

    let bearerAuthorization (TokenString token) =
        let header = Headers.AuthenticationHeaderValue("Bearer", token)
        fun (headers:Headers.HttpRequestHeaders) ->
            headers.Authorization <- header