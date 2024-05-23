namespace AADTests

open System
open System.Threading
open Xunit
open Swensen.Unquote
open System.IdentityModel.Tokens.Jwt
open AAD
open AADTests.TestsCommon
open System.Net

module Internals =
    open Microsoft.IdentityModel.Tokens
    open System.Security.Claims

    module Introspection =
        let audience = ".default"
        let introspect = 
              ((fun _ -> Async.result oidcConfig), TokenCache.mkDefault(), [Audience audience])
              |||> JwtSecurityTokenIntrospector.mkNew 
        
        [<Fact>]
        let Introspects () =
            let tokenHandler = JwtSecurityTokenHandler()
            let jwtToken =
                tokenHandler.CreateJwtSecurityToken(
                    oidcConfig.Issuer,
                    audience,
                    ClaimsIdentity([Claim("role", "Test/read/*")]),
                    Nullable DateTime.UtcNow,
                    Nullable (DateTime.UtcNow + (TimeSpan.FromHours 1.)),
                    Nullable (DateTime.UtcNow + (TimeSpan.FromHours 1.)),
                    SigningCredentials(oidcConfig.SigningKeys |> Seq.head, SecurityAlgorithms.RsaSha256))
                |> tokenHandler.WriteToken                

            async {
                let! introspected = introspect (TokenString jwtToken)
                true =! Result.isOk introspected
                return introspected
            } |> Async.RunSynchronously
        
        [<Fact>]
        let Expired () =
            let tokenHandler = JwtSecurityTokenHandler()
            let jwtToken =
                let yesterday = DateTime.Today - (TimeSpan.FromDays 1.)
                tokenHandler.CreateJwtSecurityToken(
                    oidcConfig.Issuer,
                    audience,
                    ClaimsIdentity([]),
                    Nullable yesterday,
                    Nullable (yesterday + (TimeSpan.FromHours 1.)),
                    Nullable (yesterday + (TimeSpan.FromHours 1.)),
                    SigningCredentials(oidcConfig.SigningKeys |> Seq.head, SecurityAlgorithms.RsaSha256))
                |> tokenHandler.WriteToken                

            async {
                let! introspected = introspect (TokenString jwtToken)
                true =! Result.isError introspected
            } |> Async.RunSynchronously
        
        [<Fact>]
        let ``Invalid Audience`` () =
            let tokenHandler = JwtSecurityTokenHandler()
            let jwtToken =
                tokenHandler.CreateJwtSecurityToken(
                    oidcConfig.Issuer,
                    "audience",
                    ClaimsIdentity([]),
                    Nullable DateTime.UtcNow,
                    Nullable (DateTime.UtcNow + (TimeSpan.FromHours 1.)),
                    Nullable (DateTime.UtcNow + (TimeSpan.FromHours 1.)),
                    SigningCredentials(oidcConfig.SigningKeys |> Seq.head, SecurityAlgorithms.RsaSha256))
                |> tokenHandler.WriteToken                

            async {
                let! introspected = introspect (TokenString jwtToken)
                true =! Result.isError introspected
            } |> Async.RunSynchronously
            
    module Validation =
        let ofToken p (t: JwtSecurityToken) =
            t.Claims |> Seq.collect p

        [<Fact>]
        let ``Role demand satisfied`` () =
            let token = Introspection.Introspects()
            let result =
                token 
                |> Result.bind (ResourceOwner.validate '/' (ofToken ResourceOwner.ClaimProjection.ofRole) (Pattern ["Test"; "read"; "A"]))
            true =! Result.isOk result
            
        [<Fact>]
        let ``Scope demand is not satisfied`` () =
            let token = Introspection.Introspects()
            let result =
                token 
                |> Result.bind (ResourceOwner.validate '/' (ofToken ResourceOwner.ClaimProjection.ofScope) (Pattern ["Test"; "read"; "A"]))
            true =! Result.isError result
            
        [<Fact>]
        let ``Scope demand is satisfied`` () =
            let claims = Seq.singleton (Claim("scp", "Test.read.A Test.write.B"))
            let token = JwtSecurityToken(claims = claims)
            let result =
                ResourceOwner.validate '.' (ofToken ResourceOwner.ClaimProjection.ofScope) (Pattern ["Test"; "read"; "A"]) token
            true =! Result.isOk result
            
        [<Fact>]
        let ``AppRole demand is satisfied`` () =
            let claims = [ Claim("roles", "Test/read/A"); Claim("roles", "Test/write/B") ]
            let token = JwtSecurityToken(claims = claims)
            let result =
                ResourceOwner.validate '/' (ofToken ResourceOwner.ClaimProjection.ofAppRole) (Pattern ["Test"; "read"; "A"]) token
            true =! Result.isOk result


/// Fixture to share initialization across all  3BodyProblem tests
type Parties() =
    let mutable last = None
    let init httpClient =
        async {
            match last with
            | Some args -> return args
            | _ ->
                let cts = new CancellationTokenSource()
                let! address = Sample.start cts
                                            httpClient
                                            [settings.Audience]
                                            settings.Authority
                let proxy = ResourceProxy.mkDefault (Uri address)
                                                    httpClient
                                            
                last <- Some(cts, proxy)
                return last.Value
        }
    
    interface IDisposable with
        member __.Dispose() =
            match last with
            | Some(cts,_) -> cts.Cancel()
            | _ -> ()
            
    member __.Init httpClient = init httpClient |> Async.RunSynchronously
    

[<Trait("Category","integration")>]
type ThreeBodyProblem(output: Xunit.Abstractions.ITestOutputHelper, fixture: Parties) =
    let httpClient = mkHttpClient output
    
    interface IClassFixture<Parties>

    [<Fact>]
    member __.``Admin can write and read`` () =
        async {
          let _, proxy = fixture.Init httpClient
          let requestor = 
            proxy |> AsyncRequestor.mkNew (ResourceProxy.authenticate ([settings.Scope], ClientId settings.AdminAppId, Secret settings.AdminSecret, settings.Authority))
          let! response = requestor.Call (ProxyResult.bindAsync (fun p -> p.read()))
          response =! Success "Read!"
          let! response = requestor.Call (ProxyResult.bindAsync (fun p -> p.write()))
          response =! Success "Written!"
        } |> Async.RunSynchronously 

    [<Fact>]
    member __.``Writer can write but not read`` () =
        async {
          let _, proxy = fixture.Init httpClient
          let requestor = 
            proxy |> AsyncRequestor.mkNew (ResourceProxy.authenticate ([settings.Scope], ClientId settings.WriterAppId, Secret settings.WriterSecret, settings.Authority))
          let! response = requestor.Call (ProxyResult.bindAsync (fun p -> p.read()))
          response =! AuthorizationError HttpStatusCode.Forbidden
          let! response = requestor.Call (ProxyResult.bindAsync (fun p -> p.write()))
          response =! Success "Written!"
        } |> Async.RunSynchronously 

    [<Fact>]
    member __.``Reader can read`` () =
        async {
          let _, proxy = fixture.Init httpClient
          let requestor = 
            proxy |> AsyncRequestor.mkNew (ResourceProxy.authenticate ([settings.Scope], ClientId settings.ReaderAppId, Secret settings.ReaderSecret, settings.Authority))
          let! response = requestor.Call (ProxyResult.bindAsync (fun p -> p.read()))
          response =! Success "Read!"
        } |> Async.RunSynchronously 

    [<Fact>]
    member __.``Forbidden`` () =
        async {
          let _, proxy = fixture.Init httpClient

          let! response = proxy.provision()
          response =! Success ()

          let! response = proxy.read()
          response =! AuthorizationError HttpStatusCode.Forbidden
        } |> Async.RunSynchronously 