[<AutoOpen>]
module AAD.Domain

[<Struct>]
type ClientName = ClientName of string

[<Struct>]
type Scope = Scope of string

[<Struct>]
type Audience = Audience of string

[<Struct>]
type ClientId = ClientId of System.Guid

[<Struct>]
type Secret = Secret of string

[<Struct>]
type UserName = UserName of string 

[<Struct>]
type Password = Password of string 

type Demand = 
   | Pattern of string list
   | Any of Demand list
   | All of Demand list

[<Struct>]
type TokenString = TokenString of string

[<Struct>]
type WWWAuthenticate = WWWAuthenticate of string

[<RequireQualifiedAccess>]
module Secret =
    let inline toString (Secret s) = s

[<RequireQualifiedAccess>]
module ClientId =
    let inline toGuid (ClientId id) = id
    let inline toString (ClientId id) = string id

[<RequireQualifiedAccess>]
module UserName =
    let inline format domain uid =
        sprintf "%s/%s" domain uid |> UserName

[<RequireQualifiedAccess>]
module TokenString =
    let inline toString (TokenString s) = s

[<RequireQualifiedAccess>]
module Scope =
    let inline toString (Scope scope) = scope

[<RequireQualifiedAccess>]
module Audience =
    let inline toString (Audience audience) = audience

[<RequireQualifiedAccess>]
module Demand =
    let rec private map =
        function
        | Pattern pattern ->
            let xs claim = seq { yield! claim; yield! Seq.initInfinite (fun _ -> "") } |> Seq.zip pattern
            Seq.exists (xs >> Seq.fold (fun acc (p,s) -> acc && (s = "*" || String.equalsCaseInsensitive p s)) true)
        | All demands ->
            fun claims -> (true,demands) ||> List.fold (fun acc demand -> acc && map demand claims)
        | Any demands ->
            fun claims -> (false,demands) ||> List.fold (fun acc demand -> acc || map demand claims)

    let eval (claims: #seq<string list>) (demand: Demand) =
        let mapped = map demand
        claims |> Seq.cache |> mapped


module Assembly =
    open System.Runtime.CompilerServices
    
    [<InternalsVisibleTo("AAD.Test")>]
    [<InternalsVisibleTo("AAD.tasks.Test")>]
    [<InternalsVisibleTo("AAD.Suave")>]
    [<InternalsVisibleTo("AAD.Giraffe")>]
    ()