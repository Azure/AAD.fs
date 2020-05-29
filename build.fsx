#r "paket:
nuget FSharp.Core ~> 4.6.0
nuget Fake.DotNet.Cli
nuget Fake.IO.FileSystem
nuget Fake.Core.ReleaseNotes
nuget Fake.Core.Target //"
#load "./.fake/build.fsx/intellisense.fsx"
#if !FAKE
  #r "Facades/netstandard"
#endif

open Fake.Core
open Fake.Core.TargetOperators
open Fake.DotNet
open Fake.IO
open Fake.IO.Globbing.Operators
open System
open System.Text.RegularExpressions
let release = ReleaseNotes.load "RELEASE_NOTES.md"
let ver =
    match Environment.environVarOrNone "BUILD_NUMBER" with
    | Some n -> { release.SemVer with Patch = uint32 n; Original = None }
    | _ -> SemVer.parse "0.0.0"

[<AutoOpen>]
module Shell =
    let sh cmd args cwd parse = 
        CreateProcess.fromRawCommandLine cmd args
        |> CreateProcess.withWorkingDirectory cwd
        |> CreateProcess.redirectOutput
        |> CreateProcess.ensureExitCode
        |> CreateProcess.map parse
        |> Proc.run
    let inline az arg = sh "az" arg
    let aza args cwd parse =
        async { return az args cwd parse }
    let parsePlain r = String.trimChars [|' '; '\n'|] r.Result.Output
    let mapOfTsv s = 
        Regex.Matches(s, @"(\w+)\s+([-\w]+)\s*")
        |> Seq.cast<Match>
        |> Seq.map (fun m -> m.Groups.[1].Value,m.Groups.[2].Value)
        |> Map.ofSeq

module Async =
    let tuple cont comp =
        async {
            let! x = comp
            let! y = cont
            return x,y
        }

module Graph =
    let assign roleId principalId appObjId tenantId = 
        let body = sprintf """{\"id\":\"%s\",\"principalId\":\"%s\",\"resourceId\":\"%s\"}"""
                           roleId
                           principalId
                           appObjId
        let args = 
           sprintf "rest --method post --uri \"https://graph.windows.net/%s/servicePrincipals/%s/appRoleAssignments?api-version=1.6\" --body \"%s\" --headers \"Content-type=application/json\""
                    tenantId
                    principalId
                    body
        az args "." ignore

module Secret =
    let set name value =
        sh "dotnet" (sprintf "user-secrets set \"%s\" \"%s\"" name value) "AAD.Test" ignore
    let private parseList r =
        Regex.Matches(r.Result.Output, @"(\w+)\s+=\s+([-\w]+)\n*")
        |> Seq.cast<Match>
        |> Seq.map (fun m -> m.Groups.[1].Value,m.Groups.[2].Value)
    let list project =
        sh "dotnet" "user-secrets list" project parseList

let packages =
    ["AAD.fs"
     "AAD.fs.tasks"
     "AAD.Suave"
     "AAD.Giraffe"]

Target.create "clean" (fun _ ->
    !! "./**/bin"
    ++ "./**/obj"
    |> Seq.iter Shell.cleanDir
)

Target.create "restore" (fun _ ->
    DotNet.restore id "."
)

Target.create "build" (fun _ ->
    let args = sprintf "/p:Version=%s --no-restore" ver.AsString
    DotNet.build (fun a -> a.WithCommon (fun c -> { c with CustomParams = Some args})) "."
)

Target.create "test" (fun _ ->
    let args = "--no-restore --filter \"(Category!=integration & Category!=interactive)\""
    DotNet.test (fun a -> a.WithCommon (fun c -> { c with CustomParams = Some args})) "."
)

Target.create "registerSample" (fun _ ->
    let parseApp =
        parsePlain >> String.split '\n' >> List.filter String.isNotNullOrEmpty >> function
        | [l1;l2] -> l1, mapOfTsv l2 
        | x -> failwithf "Unexpected output:%A" x
    let parseClient =
        parsePlain >> String.split '\n' >> List.filter String.isNotNullOrEmpty >> function
        | [l1;l2] -> l1, l2 
        | x -> failwithf "Unexpected output:%A" x

    let tenantId = az "account show --query tenantId --output tsv" "." parsePlain
    let rnd = Random().Next(1,1000)
    let appName = sprintf "aad-fs-sample%d" rnd
    printfn "Registring: %s" appName

    // resource server app
    let appId,roles =
        az (sprintf "ad app create --display-name %s --app-roles @Roles.json --query \"[appId,appRoles[].[displayName,id][]]\" --output tsv" appName)
            "AAD.Test"
            parseApp
    az (sprintf "ad app update --id %s --identifier-uris \"api://%s\"" appId appId) "." ignore
    az (sprintf "ad sp create --id %s" appId) "." ignore
    az (sprintf "ad sp update --id %s --add tags WindowsAzureActiveDirectoryIntegratedApp" appId) "." ignore
    let appSPId =
        az (sprintf "ad sp show --id %s --query objectId --output tsv" appId) "." parsePlain
    // client principals
    let (readerPwd,(readerId,readerAppId)),(writerPwd,(writerId,writerAppId)),(adminPwd,(adminId,adminAppId)) =
        [ sprintf "http://aad-sample-reader%d" rnd
          sprintf "http://aad-sample-writer%d" rnd
          sprintf "http://aad-sample-admin%d" rnd ]
        |> List.map (fun n ->
            aza (sprintf "ad sp create-for-rbac -n \"%s\" --query password --output tsv" n) "." parsePlain
            |> Async.tuple (aza (sprintf "ad sp show --id \"%s\" --query \"[objectId,appId]\" --output tsv" n) "." parseClient))
        |> Async.Parallel
        |> Async.RunSynchronously
        |> function [|r1; r2; r3|] -> r1, r2, r3 | _ -> failwith "Arity mismatch"
    // role assignment
    Graph.assign (roles |> Map.find "Reader") readerId appSPId tenantId 
    Graph.assign (roles |> Map.find "Writer") writerId appSPId tenantId
    Graph.assign (roles |> Map.find "Admin") adminId appSPId tenantId

    Secret.set "AppId" appId
    Secret.set "ReaderAppId" readerAppId
    Secret.set "ReaderSecret" readerPwd
    Secret.set "WriterAppId" writerAppId
    Secret.set "WriterSecret" writerPwd
    Secret.set "AdminAppId" adminAppId
    Secret.set "AdminSecret" adminPwd
    Secret.set "TenantId" tenantId
)

Target.create "unregisterSample" (fun _ ->
    let secrets = Secret.list "AAD.Test" |> Map.ofSeq
    [ secrets.["AppId"] 
      secrets.["AdminAppId"]
      secrets.["ReaderAppId"]
      secrets.["WriterAppId"] ]
    |> List.map (fun id -> aza (sprintf "ad sp delete --id %s" id) "." ignore)
    |> Async.Parallel
    |> Async.RunSynchronously
    |> ignore
)

Target.create "integration" (fun _ ->
    let args = "--no-restore --filter \"Category = integration\""
    DotNet.test (fun a -> a.WithCommon (fun c -> { c with CustomParams = Some args})) "."
)

Target.create "package" (fun _ ->
    let args = sprintf "/p:Version=%s --no-restore" ver.AsString
    packages
    |> List.iter (DotNet.pack (fun a -> a.WithCommon (fun c -> { c with CustomParams = Some args })))
)

Target.create "publish" (fun _ ->
    let exec dir =
        DotNet.exec (fun a -> a.WithCommon (fun c -> { c with WorkingDirectory=dir }))
    packages
    |> List.iter (fun folder ->
        let args = sprintf "push %s.%s.nupkg -s %s -k %s"
                           folder ver.AsString
                           (Environment.environVar "NUGET_REPO_URL")
                           (Environment.environVar "NUGET_REPO_KEY")
        let result = exec (folder + "/bin/Release") "nuget" args
        if (not result.OK) then failwithf "%A" result.Errors)
)

Target.create "meta" (fun _ ->
    [ "<Project xmlns=\"http://schemas.microsoft.com/developer/msbuild/2003\">"
      "<PropertyGroup>"
      "<PackageProjectUrl>https://github.com/Azure/AAD.fs</PackageProjectUrl>"
      "<PackageLicense>MIT</PackageLicense>"
      "<RepositoryUrl>https://github.com/Azure/AAD.fs.git</RepositoryUrl>"
      sprintf "<PackageReleaseNotes>%s</PackageReleaseNotes>" (List.head release.Notes)
      "<PackageTags>suave;giraffe;fsharp</PackageTags>"
      sprintf "<Version>%s</Version>" (string ver)
      "</PropertyGroup>"
      "</Project>"]
    |> File.write false "Directory.Build.props"
)

Target.create "release" ignore

"clean"
  ==> "restore"
  ==> "build"
  ==> "test"
  ==> "package"
  ==> "publish"

"integration"
 <== [ "test" ]

"release"
 <== [ "meta"; "publish" ]

Target.runOrDefault "test"