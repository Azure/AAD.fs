[<AutoOpen>]
module AADTests.TestsCommon

open Serilog
open System.Net.Http
open Microsoft.IdentityModel.Protocols.OpenIdConnect
open Microsoft.IdentityModel.Protocols

let mkNonRedirectingHandler () =
    new HttpClientHandler(AllowAutoRedirect = false)

let mkHttpClientWith<'test> (output:Xunit.Abstractions.ITestOutputHelper) handler =
    let logger = LoggerConfiguration()
                    .MinimumLevel.Verbose()
                    .WriteTo.TestOutput(output, Events.LogEventLevel.Verbose)
                    .CreateLogger()
                    .ForContext<'test>()
    
    let log template args =
        logger.Verbose(template, args |> Seq.map snd |> Array.ofSeq)

    new HttpClient(new Logging.HttpClientLogger(handler,log) :> HttpMessageHandler)

let mkHttpClient<'test> (output:Xunit.Abstractions.ITestOutputHelper) =
    mkHttpClientWith output (new HttpClientHandler())

let settings = Settings.Load()
let oidcConfig = 
    OpenIdConnectConfigurationRetriever
        .GetAsync("OpenIdConnectMetadata.json",
                  FileDocumentRetriever(),
                  System.Threading.CancellationToken.None)
        .Result


module Http =
    open System.Net
    
    let waitFor method (period:int) url =
        async {
            use client = new HttpClient()
            let rec poll sleep =
                async {
                    if sleep then do! Async.Sleep period
                    use request = new HttpRequestMessage(Method = HttpMethod(method),
                                                         RequestUri = System.Uri(url, System.UriKind.Absolute))
                    let! response = client.SendAsync request |> Async.AwaitTask |> Async.Catch
                    match response with
                    | Choice1Of2 r when r.StatusCode = HttpStatusCode.NoContent -> ()
                    | Choice1Of2 r ->
                        return! poll true
                    | Choice2Of2 ex -> 
                        return! poll true
                }
            return! poll false
        }
