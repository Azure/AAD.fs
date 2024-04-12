namespace AADTests

open System
open System.Threading
open System.Threading.Tasks
open Xunit
open Swensen.Unquote
open AAD
open AADTests.TestsCommon
    

/// Fixture to share initialization across all  3BodyProblem tests
type Parties() =
    let mutable last = None
    let init httpClient =
        backgroundTask {
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
            
    member __.Init httpClient = (init httpClient).Result
    

[<Trait("Category","integration")>]
type ThreeBodyProblem(output: Xunit.Abstractions.ITestOutputHelper, fixture: Parties) =
    let httpClient = mkHttpClient output
    
    interface IClassFixture<Parties>

    [<Fact>]
    member __.``Admin can write and read`` () =
        backgroundTask {
          let _, proxy = fixture.Init httpClient
          let requestor = 
            proxy |> TaskRequestor.mkNew (ResourceProxy.authenticate ([settings.Scope], ClientId settings.AdminAppId, Secret settings.AdminSecret, settings.Authority))
          let! response = requestor.Call (fun p -> p.read())
          response =! "Read!"
          let! response = requestor.Call (fun p -> p.write())
          response =! "Written!"
        }

    [<Fact>]
    member __.``Writer can write but not read`` () =
        backgroundTask {
          let _, proxy = fixture.Init httpClient
          let requestor = 
            proxy |> TaskRequestor.mkNew (ResourceProxy.authenticate ([settings.Scope], ClientId settings.WriterAppId, Secret settings.WriterSecret, settings.Authority))
          try
            let! _ = proxy.read()
            ()
          with
            :? ProxyException as e when e.Denied -> ()
          let! response = requestor.Call (fun p -> p.write())
          response =! "Written!"
        }

    [<Fact>]
    member __.``Reader can read`` () =
        backgroundTask {
          let _, proxy = fixture.Init httpClient
          let requestor = 
            proxy |> TaskRequestor.mkNew (ResourceProxy.authenticate ([settings.Scope], ClientId settings.ReaderAppId, Secret settings.ReaderSecret, settings.Authority))
          let! response = requestor.Call (fun p -> p.read())
          response =! "Read!"
        }

    [<Fact>]
    member __.``Forbidden`` () =
        backgroundTask {
          let _, proxy = fixture.Init httpClient
          let! response = proxy.provision() // should always succeed

          try
            let! _ = proxy.read()
            ()
          with
            :? ProxyException as e when e.Denied -> ()
        } 