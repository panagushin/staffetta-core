using System.Reflection;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace Staffetta.Core.Tests;

[TestClass]
public sealed class CoreAssemblyTests
{
    [TestMethod]
    public void CoreAssemblyLoads()
    {
        var assembly = Assembly.Load("Staffetta.Core");

        Assert.AreEqual("Staffetta.Core", assembly.GetName().Name);
    }
}
