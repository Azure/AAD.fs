namespace AAD

module Readers =
    open Suave
    open AAD.Domain

    module internal TokenString =
        let inline ofChoice choice =
            match choice with
            | Choice2Of2 s
            | Choice1Of2 s -> TokenString s

    let bearer ctx =
        ctx.request.header "Authorization"
        |> Choice.map (String.trim >> String.split ' ') 
        |> Choice.bind (function ["Bearer"; token] -> Choice1Of2 token | _ -> Choice2Of2 "")
        |> Choice.bindSnd (fun _ -> Choice2Of2 "")

    let bearerTokenString =
        bearer >> TokenString.ofChoice 
