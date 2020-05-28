[<AutoOpen>]
module AADTests.Environment
open System
open Microsoft.Extensions.Configuration
open AAD

[<CLIMutable>]
type Settings =
    { AppId: Guid
      ReaderAppId: Guid
      ReaderSecret: string
      WriterAppId: Guid
      WriterSecret: string
      AdminAppId: Guid
      AdminSecret: string
      TenantId: string }
with
    member x.Audience = sprintf "api://%O" x.AppId |> Audience
    member x.Scope = sprintf "api://%O/.default" x.AppId |> Scope
    member x.Authority = sprintf "https://login.microsoftonline.com/%s" x.TenantId |> Uri
    static member Default =
        { AppId = Guid.Empty
          ReaderAppId = Guid.Empty
          ReaderSecret = ""
          WriterAppId = Guid.Empty
          WriterSecret = ""
          AdminAppId = Guid.Empty
          AdminSecret = ""
          TenantId = "" }

    static member Load() =
        let config = ConfigurationBuilder()
                        .AddUserSecrets<Settings>()
                        .Build()
        let settings = Settings.Default
        config.Bind settings
        settings
