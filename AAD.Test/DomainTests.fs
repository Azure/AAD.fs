namespace AADTests

open Xunit
open Swensen.Unquote
open AAD
    
module DemandTests =

    [<Fact>]
    let ``All when empty`` () =
        All []
        |> Demand.eval [] =! true

    [<Fact>]
    let ``All when present`` () =
        All [Pattern ["A";"1"]; Pattern ["B";"2"]]
        |> Demand.eval [["A";"1"]; ["B";"2"]] =! true

    [<Fact>]
    let ``All when absent`` () =
        All [Pattern ["A";"1"]; Pattern ["B";"2"]]
        |> Demand.eval [["A";"1"]] =! false

    [<Fact>]
    let ``Any when present`` () =
        Any [Pattern ["A";"1"]; Pattern ["B";"2"]]
        |> Demand.eval [["A";"1"]] =! true

    [<Fact>]
    let ``Any when absent`` () =
        Any [Pattern ["A";"1"]; Pattern ["B";"2"]]
        |> Demand.eval [] =! false

    [<Fact>]
    let ``Pattern no match`` () =
        Pattern ["A";"1"]
        |> Demand.eval [["";""]; ["A"]; ["1"]] =! false


    [<Fact>]
    let ``Pattern exact match`` () =
        Pattern ["A";"1"]
        |> Demand.eval [["A";"1"]] =! true

    [<Fact>]
    let ``Pattern whildcard match`` () =
        Pattern ["A";"1"]
        |> Demand.eval [["*";"*"]] =! true

    [<Fact>]
    let ``Partial whildcard match`` () =
        Pattern ["A";"1"]
        |> Demand.eval [["*"; "*"; "*"]] =! true
