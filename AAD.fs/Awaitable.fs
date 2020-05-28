namespace AAD

open System

[<AutoOpen>]
module internal AwaitableBuilder =
    open System.Threading.Tasks
#if TASKS
    open FSharp.Control.Tasks
    let awaitable = task
    type Awaitable<'r> = Task<'r>

    [<RequireQualifiedAccess>]
    module Awaitable =
        let inline result x = Task.FromResult x
        let inline awaitTask x = x
        let inline awaitUnitTask (x:Task) = x.ContinueWith<unit>(fun _ -> ())
        let inline awaitAsync x = Async.StartAsTask x
        let inline map f (x:Task<_>) = task { let! v = x in return f v }
        let inline bind f (x:Task<_>) = task { let! v = x in return! f v }
        let inline whenAll (xs:#seq<Task<'t>>) = Task.WhenAll<'t> (Array.ofSeq xs)
#else
    let awaitable = async
    type Awaitable<'r> = Async<'r>

    [<RequireQualifiedAccess>]
    module Awaitable =
        let inline result x = async.Return x
        let inline awaitTask x = Async.AwaitTask x
        let inline awaitUnitTask (x:Task) = Async.AwaitTask x
        let inline awaitAsync x = x
        let inline map f x = async { let! v = x in return f v }
        let inline bind f x = async { let! v = x in return! f v }
        let inline whenAll x = Async.Parallel x
#endif
