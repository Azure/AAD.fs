module AADTests.Logging

open System.Threading
open System.Threading.Tasks
open System.Net.Http

type Log = string -> (string*obj) list -> unit

type HttpClientLogger(innerHandler, log:Log) =
    inherit DelegatingHandler(innerHandler)
    member private __.baseImpl (request, cancellationToken) = base.SendAsync (request, cancellationToken)
    override this.SendAsync(request:HttpRequestMessage, cancellationToken:CancellationToken):Task<HttpResponseMessage> =
        
        backgroundTask {
            if isNull request.Content then
                log "Request: {req}" ["req", box request]
            else
                let! content = request.Content.ReadAsStringAsync()
                log "Request: {req}, Content: {content}" ["content",box content
                                                          "req", box request]
            
            let! response = this.baseImpl (request, cancellationToken)

            if isNull response.Content then
                log "Response: {resp}" ["resp",box response]
            else        
                let! content = response.Content.ReadAsStringAsync()
                log "Response: {resp}, Content: {content}" ["resp", box response
                                                            "content", box content]

            return response
        }
