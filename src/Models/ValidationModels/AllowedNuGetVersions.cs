namespace Limbo.Test.Helpers.NuGetPackageCheck.Models.ValidationModels;
public class AllowedNuGetVersions {
    public static object[] GetTestCases =
    {
        new object[] { "Swashbuckle.AspNetCore", "6.6.2", "" },
        new object[] { "NUnit", "4.2.2", "Limbo.Test.Security"}
    };
}