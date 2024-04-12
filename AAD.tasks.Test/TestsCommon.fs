module AADTests.TestsCommon

open System
open Serilog
open System.Net.Http
open System.Threading.Tasks
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
        backgroundTask {
            use client = new HttpClient()
            let rec poll sleep =
                backgroundTask {
                    if sleep then do! Async.Sleep period
                    use request = new HttpRequestMessage(Method = HttpMethod(method),
                                                         RequestUri = Uri(url, UriKind.Absolute))
                    try
                        let! r = client.SendAsync request
                        if r.StatusCode <> HttpStatusCode.NoContent then return! poll true
                    with _ -> 
                        return! poll true
                }
            return! poll false
        }

    open Microsoft.AspNetCore.Hosting
    open Giraffe
    
    let startServer (cl: System.Threading.CancellationToken, ip, port:uint16) router =
        let configureApp (app : Microsoft.AspNetCore.Builder.IApplicationBuilder) =
            // Add Giraffe to the ASP.NET Core pipeline
            app.UseGiraffe router

        let configureServices (services : Microsoft.Extensions.DependencyInjection.IServiceCollection) =
            // Add Giraffe dependencies
            services.AddGiraffe() |> ignore

        Task.Factory.StartNew(fun _ ->
            WebHostBuilder()
                .UseKestrel()
                .UseUrls(sprintf "http://%O:%d" ip (int port))
                .Configure(Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> configureApp)
                .ConfigureServices(configureServices)
                .Build()
                .Run()    
        ,cl)

module Task =
    let inline wait (t: Task<_>) =
        t.Wait()
        t.Result