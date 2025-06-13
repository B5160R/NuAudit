# NuAudit

NuAudit is a .NET tool for auditing NuGet package vulnerabilities and license compliance across all projects in a solution.

## Features

- Scans all `.csproj` files in a solution for NuGet package references.
- Checks for known vulnerabilities using the NuGet API.
- Identifies packages with licenses not in an allowed set.
- Provides utilities to display vulnerability and license information.

## Usage

1. **Build the project:**

   ```sh
   dotnet build
   ```

2. **Run tests:**

   ```sh
   dotnet test
   ```

3. **Integrate NuAudit in your code:**

   ```
   csharp
   var auditor = new NuAudit.NuAudit();

   // Get all vulnerable packages
   var vulnerabilities = await auditor.GetVulnerablePackagesAsync();
   auditor.DisplayVulnerabilityDetails(vulnerabilities);

   // Check for restricted licenses
   var allowedLicenses = new HashSet<string> { "MIT", "Apache-2.0" };
   var restricted = await auditor.GetPackagesWithRestrictedLicensesAsync(allowedLicenses);
   ```

## Project Structure

- [`src/NuAudit.cs`](src/NuAudit.cs): Main auditing logic.
- [`src/Models/NugetPackageModels/`](src/Models/NugetPackageModels/): Data models for package info, vulnerabilities, and licenses.
- [`src/UnitTest1.cs`](src/UnitTest1.cs): Example unit test.

## Requirements

- .NET 9.0 SDK or later
- Internet access (for querying NuGet API)

## License

[MIT]