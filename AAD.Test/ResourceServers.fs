[<AutoOpen>]
module AADTests.ResourceServers

open System
open System.Threading
open System.Net
open Suave
open Suave.Filters
open Suave.Operators
open AAD
open AADTests.TestsCommon

let rnd = Random()
module Sample =

    let start (cts:CancellationTokenSource) httpClient audience authority =
        let testPort = uint16 (rnd.Next(1,1000)+52767)
        let conf = { defaultConfig with 
                        cancellationToken = cts.Token
                        bindings = [HttpBinding.create HTTP IPAddress.Loopback testPort] }
        async {
            let! protector = 
                PartProtector.mkDefault httpClient audience authority
                
            let read : WebPart =
                protector.Verify (fun ctx -> Async.result <| Pattern ["items"; "r"])
                                 (fun token -> Successful.OK "Read!")
            let write : WebPart =
                protector.Verify (fun ctx -> Async.result <| Pattern ["items"; "w"])
                                 (fun token -> Successful.OK "Written!")
        
            let app = 
                choose [
                  HEAD >=> path "/" >=> Successful.NO_CONTENT
                  GET >=> path "/" >=> read
                  PUT >=> path "/" >=> write
                  RequestErrors.NOT_FOUND ""
                ]
            let listening, server = startWebServerAsync conf app
            
            Async.Start(server, cts.Token)
            let address = sprintf "http://localhost:%d" testPort
            do! address |> Http.waitFor "HEAD" 10_000 
            return address
        }
    
