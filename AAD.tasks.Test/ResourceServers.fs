[<AutoOpen>]
module AADTests.ResourceServers

open System
open System.Threading
open System.Threading.Tasks
open System.Net
open Giraffe
open FSharp.Control.Tasks.V2.ContextInsensitive
open AAD
open AADTests.TestsCommon

let rnd = Random()
module Sample =

    let start (cts:CancellationTokenSource) httpClient audience authority =
        task {
            let testPort = uint16 (rnd.Next(1,1000)+52767)
            let conf = (cts.Token,IPAddress.Loopback,testPort)
            
            let! protector = 
                PartProtector.mkDefault httpClient audience authority
                
            let read : HttpHandler =
                protector.Verify (fun ctx -> Task.FromResult <| Pattern ["items"; "r"])
                                 (fun token -> text "Read!")
        
            let write : HttpHandler =
                protector.Verify (fun ctx -> Task.FromResult <| Pattern ["items"; "w"])
                                 (fun token -> text "Written!")
                
            let app = 
                choose [
                  HEAD >=> route "/" >=> Successful.NO_CONTENT
                  GET >=> route "/" >=> read
                  PUT >=> route "/" >=> write
                  RequestErrors.NOT_FOUND ""
                ]
            let _ = Http.startServer conf app
            
            let address = sprintf "http://localhost:%d" testPort
            do! address |> Http.waitFor "HEAD" 10_000 
            return address
        }
    

