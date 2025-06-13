using System.Collections.Generic;

namespace Limbo.Test.Helpers.NuGetPackageCheck.Models.ValidationModels;
public class AllowedLicsenses {
    public static IEnumerable<HashSet<string>> GetTestCases() {
        yield return new HashSet<string> {
            "MIT",
            "Microsoft",
            "Apache-2.0"
        };
    }
}