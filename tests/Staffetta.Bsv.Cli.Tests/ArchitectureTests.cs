using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Staffetta.Bsv.Cli.Tests;

[TestClass]
public sealed class ArchitectureTests
{
    [TestMethod]
    public void CoreDoesNotReferenceCliAndTransportAuthorityRemainsInternal()
    {
        var core = Assembly.Load("Staffetta.Core");
        Assert.IsFalse(core.GetReferencedAssemblies().Any(reference => reference.Name == "Staffetta.Bsv.Cli"));

        var actor = core.GetType(
            "Staffetta.Core.Protocol.Transport.BsvPeerStreamTransportActor",
            throwOnError: true)!;
        Assert.IsFalse(actor.IsPublic);
        Assert.IsFalse(actor.IsNestedPublic);
    }

    [TestMethod]
    public void CliExportsNoLibraryApi()
    {
        var cli = Assembly.Load("Staffetta.Bsv.Cli");
        Assert.HasCount(0, cli.GetExportedTypes());
    }
}
