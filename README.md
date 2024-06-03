## F# Web API endpoint protection using Azure AD roles

[![Build](https://github.com/Azure/AAD.fs/actions/workflows/azure.aad.fs.yml/badge.svg)](https://github.com/Azure/AAD.fs/actions/workflows/azure.aad.fs.yml)
[![NuGet](https://img.shields.io/nuget/v/AAD.fs.svg?style=flat)](https://www.nuget.org/packages/AAD.fs/)

#### Consuming the library

The library ships as following packages:

- AAD.fs: F# abstractions with `Async` public interfaces
- AAD.fs.tasks: F# abstractions with `Task` public interfaces
- AAD.Suave: Suave-specific wrappers 
- AAD.Giraffe: Giraffe-specific wrappers 

##### For resource server
- Use Suave or Giraffe package and `PartProtector` abstraction, alternatively build on the base AAD.fs `ResourceOwner` primitives
- Use `Noop.PartProtector` to bypass the verification of demands (for example to implement feature switch)

##### For requesting party
- Use `AsyncRequestor` or `TaskRequestor` from AAD.fs package or [Identity platform SDK](https://learn.microsoft.com/en-us/entra/identity-platform/v2-overview) library directly.

#### Building

##### Prerequisites
The build requires at least .NET Core SDK 8 installed.
When building for the first time restore the local tools, in this directory run:

* `dotnet tool restore`, then
* `dotnet fsi build.fsx` or try `./build.fsx --list` to see the available targets.

#### Test scenario
The test scenario implements authorization using [Azure Application Roles](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-app-roles-in-azure-ad-apps). The sample application can be found in your Azure Active Directory once provisioned:
- Search Enterprise Applications for user and group role assignments
- See Applications for the manfest of the registered application and the information about associated URI and the service principal.

##### Running integration tests
* Make sure you are logged in: `az login`
* Only once: Register the application and service principals: `dotnet fsi build.fsx -t registerSample`
* `dotnet fsi build.fsx -t integration`
> The build script is implemented using [FAKE](https://fake.build/fake-gettingstarted.html).

The registrated application and principals are kept in your Azure subscription and information about them - in your `dotnet user-secrets`, 
when you no longer need them, you can delete them with `dotnet fsi build.fsx -t unregisterSample`.

> Note: 
> Integration tests demonstrate a couple approaches in requestor error handling:
> * Async-based implementation uses custom result type to avoid throwing exceptions
> * Task-based implementation depends on the consumer code to handle the exceptions
>
> Either approach can be used with either version of the requestor.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
