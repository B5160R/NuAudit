using System.Xml.Linq;
using Limbo.Test.Helpers.NuGetPackageCheck.Models.NuGetPackageModels;
using NuGet.Common;
using NuGet.Packaging.Core;
using NuGet.Protocol;
using NuGet.Protocol.Core.Types;
using NuGet.Versioning;

namespace NuAudit;

#nullable enable

/// <summary>
/// Provides utilities for checking NuGet package vulnerabilities and license compliance across all projects in a solution.
/// </summary>
public class Auditor
{
    private readonly string[] _projectFiles;
    private PackageMetadataResource _nugetResource;

    /// <summary>
    /// Initializes a new instance of the <see cref="NuAudit"/> class.
    /// Scans the solution directory for all .csproj files and prepares the NuGet resource for metadata queries.
    /// </summary>
    public Auditor()
    {
        var solutionDirectory = FindSolutionFilDirectory();
        _projectFiles = Directory.GetFiles(solutionDirectory, "*.csproj", SearchOption.AllDirectories);
        Setup().GetAwaiter().GetResult();
    }

    /// <summary>
    /// Sets up the NuGet metadata resource for querying package information.
    /// </summary>
    [SetUp]
    public async Task Setup()
    {
        _nugetResource = await GetNugetResourceAsync();
        if (_nugetResource == null)
        {
            throw new Exception("Failed to retrieve NuGet resource.");
        }
    }

    /// <summary>
    /// Retrieves NuGet metadata for a specific package reference.
    /// </summary>
    /// <param name="packageReference">The package reference to query.</param>
    /// <returns>The package metadata, or <c>null</c> if not found.</returns>
    public async Task<IPackageSearchMetadata?> GetNuGetMetadataAsync(PackageInfo packageReference)
    {
        var packageIdentity = new PackageIdentity(packageReference.NuGetPackage, NuGetVersion.Parse(packageReference.Version));
        return await _nugetResource.GetMetadataAsync(packageIdentity, new SourceCacheContext(), NullLogger.Instance, default);
    }

    /// <summary>
    /// Gets all NuGet package references from all discovered project files in the solution.
    /// </summary>
    /// <returns>An enumerable of <see cref="PackageInfo"/> objects.</returns>
    public IEnumerable<PackageInfo> GetAllPackageReferences()
    {
        var packageReferences = new List<PackageInfo>();
        foreach (var projectFile in _projectFiles)
        {
            packageReferences.AddRange(ListNuGetPackages(projectFile));
        }
        return packageReferences;
    }

    /// <summary>
    /// Finds all packages with known vulnerabilities in the solution.
    /// </summary>
    /// <returns>
    /// An enumerable of <see cref="PackageVulnerabilityInfo"/> for packages with vulnerabilities.
    /// </returns>
    public async Task<IEnumerable<PackageVulnerabilityInfo>> GetVulnerablePackagesAsync()
    {
        var vulnerableNuGetPackages = new List<PackageVulnerabilityInfo>();
        foreach (var packageReference in GetAllPackageReferences())
        {
            IPackageSearchMetadata? metadata = await GetNuGetMetadataAsync(packageReference);
            if (metadata == null)
            {
                Console.WriteLine($"No metadata found for {packageReference.NuGetPackage} ({packageReference.Version}) in {packageReference.Project}");
                continue;
            }
            var vulnerabilities = metadata.Vulnerabilities ?? Enumerable.Empty<PackageVulnerabilityMetadata>();

            if (vulnerabilities.Any())
                vulnerableNuGetPackages.Add(new PackageVulnerabilityInfo {
                    NuGetPackage = packageReference.NuGetPackage,
                    Version = packageReference.Version,
                    Project = packageReference.Project,
                    Vulnerabilities = vulnerabilities.ToList()
                });
        }
        return vulnerableNuGetPackages;
    }

    /// <summary>
    /// Displays details about package vulnerabilities to the console.
    /// </summary>
    /// <param name="vulnerabilities">The vulnerabilities to display.</param>
    public void DisplayVulnerabilityDetails(IEnumerable<PackageVulnerabilityInfo> vulnerabilities) {
        if (!vulnerabilities.Any()) {
            Console.WriteLine("No vulnerable packages found.");
            return;
        }
        foreach (var vulnerability in vulnerabilities) {
            Console.WriteLine($"Package: {vulnerability.NuGetPackage}");
            Console.WriteLine($"  Version: {vulnerability.Version}");
            Console.WriteLine($"  Project: {vulnerability.Project}");
            foreach (var metadata in vulnerability.Vulnerabilities) {
                Console.WriteLine($"    Severity: {metadata.Severity}");
                Console.WriteLine($"    Advisory URL: {metadata.AdvisoryUrl}");
            }
        }
    }

    /// <summary>
    /// Finds all packages whose licenses are not in the allowed set.
    /// </summary>
    /// <param name="allowedLicenses">A set of allowed license identifiers.</param>
    /// <returns>
    /// An enumerable of <see cref="PackageLicenseInfo"/> for packages with restricted licenses.
    /// </returns>
    public async Task<IEnumerable<PackageLicenseInfo>> GetPackagesWithRestrictedLicensesAsync(HashSet<string> allowedLicenses) {
        var restrictedNuGetPackages = new List<PackageLicenseInfo>();
        foreach (var packageReference in GetAllPackageReferences()) {
            var metadata = await GetNuGetMetadataAsync(packageReference);
            if (metadata == null) {
                Console.WriteLine($"No metadata found for {packageReference.NuGetPackage} ({packageReference.Version}) in {packageReference.Project}");
                continue;
            }
            var license = metadata.LicenseMetadata?.License ?? metadata.Authors;

            if (!allowedLicenses.Contains(license)) {
                restrictedNuGetPackages.Add(new PackageLicenseInfo {
                    NuGetPackage = packageReference.NuGetPackage,
                    Version = packageReference.Version,
                    Project = packageReference.Project,
                    License = license
                });
            }
        }
        return restrictedNuGetPackages;
    }

    /// <summary>
    /// Gets all references to a specific NuGet package in the solution, optionally filtered by project name.
    /// </summary>
    /// <param name="nugetPackageName">The NuGet package name to search for.</param>
    /// <param name="projectName">Optional project name to filter by.</param>
    /// <returns>An enumerable of <see cref="PackageInfo"/> objects.</returns>
    public IEnumerable<PackageInfo> GetPackageInProjects(string nugetPackageName, string projectName = "") {
        var projectFiles = string.IsNullOrEmpty(projectName)
            ? _projectFiles
            : _projectFiles.Where(p => p.Contains(projectName)).ToArray();

        var packages = new List<PackageInfo>();
        foreach (var projectFile in projectFiles) {
            packages.AddRange(ListNuGetPackages(projectFile).ToList());
        }
        var packageInProjects = packages.Where(p => p.NuGetPackage.Equals(nugetPackageName, StringComparison.OrdinalIgnoreCase)).ToList();
        return packageInProjects;
    }

    /// <summary>
    /// Gets all references to a specific NuGet package in the specified project(s).
    /// </summary>
    /// <param name="projectName">The project name to filter by.</param>
    /// <param name="nugetPackageName">The NuGet package name to search for.</param>
    /// <returns>An enumerable of <see cref="PackageInfo"/> objects.</returns>
    public IEnumerable<PackageInfo> GetNuGetPackagesInProjects(string projectName, string nugetPackageName) {
        var projectFiles = string.IsNullOrEmpty(projectName)
            ? _projectFiles
            : _projectFiles.Where(p => p.Contains(projectName)).ToArray();

        var packages = new List<PackageInfo>();
        foreach (var projectFile in projectFiles) {
            packages.AddRange(ListNuGetPackages(projectFile).ToList());
        }
        List<PackageInfo> packageInProjects = packages.Where(p => p.NuGetPackage.Equals(nugetPackageName, StringComparison.OrdinalIgnoreCase)).ToList();
        return packageInProjects;
    }

    /// <summary>
    /// Parses a .csproj file and returns all NuGet package references.
    /// </summary>
    /// <param name="projectFilePath">The path to the .csproj file.</param>
    /// <returns>An enumerable of <see cref="PackageInfo"/> objects.</returns>
    private static IEnumerable<PackageInfo> ListNuGetPackages(string projectFilePath) {
        return XDocument
            .Load(projectFilePath)
            .Descendants("PackageReference")
            .Select(packageReference => new PackageInfo {
                Project = Path.GetFileNameWithoutExtension(projectFilePath),
                NuGetPackage = packageReference.Attribute("Include")?.Value ?? string.Empty,
                Version = packageReference.Attribute("Version")?.Value ?? string.Empty
            });
    }

    /// <summary>
    /// Retrieves the NuGet metadata resource for querying package information.
    /// </summary>
    /// <returns>The <see cref="PackageMetadataResource"/> instance.</returns>
    private async Task<PackageMetadataResource> GetNugetResourceAsync() {
        var repository = Repository.Factory.GetCoreV3("https://api.nuget.org/v3/index.json");
        return await repository.GetResourceAsync<PackageMetadataResource>();
    }

    /// <summary>
    /// Finds the solution directory by searching for a .sln file in the current or parent directories.
    /// </summary>
    /// <returns>The full path to the solution directory.</returns>
    /// <exception cref="FileNotFoundException">Thrown if no solution file is found.</exception>
    private string FindSolutionFilDirectory() {
        var dir = new DirectoryInfo(Directory.GetCurrentDirectory());
        while (dir != null) {
            var sln = dir.GetFiles("*.sln").FirstOrDefault();
            if (sln != null)
                return sln.Directory?.FullName ?? throw new FileNotFoundException("Solution file found but directory is null.");
            dir = dir.Parent;
        }
        throw new FileNotFoundException("Solution file not found in the current directory or any parent directory.");
    }
}