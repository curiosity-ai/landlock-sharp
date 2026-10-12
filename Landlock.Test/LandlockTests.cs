namespace Sandbox.Test;

using Sandbox;
using System;
using System.IO;

[TestClass]
public class LandlockTests
{
    private const string AllowedDir = "/tmp/landlock-test/allowed";
    private const string BlockedDir = "/tmp/landlock-test/blocked";

    [ClassInitialize]
    public static void GlobalSetup(TestContext _)
    {
        if (Directory.Exists(AllowedDir)) Directory.Delete(AllowedDir, true);
        if (Directory.Exists(BlockedDir)) Directory.Delete(BlockedDir, true);
        Directory.CreateDirectory(AllowedDir);
        Directory.CreateDirectory(BlockedDir);

        File.WriteAllText(Path.Combine(AllowedDir, "hello.txt"), "hello");
        File.WriteAllText(Path.Combine(BlockedDir, "secret.txt"), "blocked");
    }

    [TestMethod]
    public void GetVersionWorks()
    {
        int abi = Landlock.GetAbiVersion();
        Assert.IsGreaterThanOrEqualTo(1, abi, "ABI version must be >=1");
    }

    [TestMethod]
    public void CreateRuleset()
    {
        bool worked = false;
        try
        {
            Landlock.CreateRuleset(Landlock.FileSystem.CORE);
            worked = true;
        }
        catch
        {
            throw new Exception();
        }

        Assert.IsTrue(worked, "Landlock ruleset failed to be created");
    }
    
    [TestMethod]
    public void LandlockEnforcesFileRestrictions()
    {
        bool readFailedToBlocked  = false;
        bool writeFailedToBlocked = false;
        bool readWorkedToReadOnlyAllowed = false;
        bool writeFailedToReadOnlyAllowed = false;

        var threadWithLandlock = new Thread(() =>
        {
            var sandbox  = Landlock.CreateRuleset(Landlock.FileSystem.CORE);

            sandbox.AddPathBeneathRule(AllowedDir, Landlock.FileSystem.READ_FILE,  Landlock.FileSystem.READ_DIR);
            sandbox.Enforce();

            try
            {
                string contents = File.ReadAllText(Path.Combine(AllowedDir, "hello.txt"));
                Assert.AreEqual("hello", contents);
                readWorkedToReadOnlyAllowed = true;
            }
            catch (Exception E)
            {
                readWorkedToReadOnlyAllowed = false;
            }

            try
            {
                File.ReadAllText(Path.Combine(BlockedDir, "secret.txt"));
                readFailedToBlocked = false;
            }
            catch(Exception E)
            {
                readFailedToBlocked = true;
            }

            try
            {
                using var f = File.OpenWrite(Path.Combine(BlockedDir, "newfile.txt"));
                writeFailedToBlocked = false;
            }
            catch (Exception E)
            {
                writeFailedToBlocked = true;
            }

            try
            {
                using var f = File.OpenWrite(Path.Combine(AllowedDir, "newfile.txt"));
                writeFailedToReadOnlyAllowed = false;
            }
            catch (Exception E)
            {
                writeFailedToReadOnlyAllowed = true;
            }
        });

        threadWithLandlock.Start();
        threadWithLandlock.Join();

        Assert.IsTrue(readFailedToBlocked,          "Reading from a blocked directory should fail");
        Assert.IsTrue(writeFailedToBlocked,         "Writing to a blocked directory should fail");
        Assert.IsTrue(readWorkedToReadOnlyAllowed,  "Reading from an read-only allowed directory should work");
        Assert.IsTrue(writeFailedToReadOnlyAllowed, "Writing to an read-only allowed directory should fail");


        bool notEnforcedReadFailedToBlocked = false;
        bool notEnforcedWriteFailedToBlocked = false;
        bool notEnforcedReadWorkedToReadOnlyAllowed = false;
        bool notEnforcedWriteFailedToReadOnlyAllowed = false;

        var threadWithoutLandlock = new Thread(() =>
        {
            try
            {
                string contents = File.ReadAllText(Path.Combine(AllowedDir, "hello.txt"));
                Assert.AreEqual("hello", contents);
                notEnforcedReadWorkedToReadOnlyAllowed = true;
            }
            catch (Exception E)
            {
                notEnforcedReadWorkedToReadOnlyAllowed = false;
            }

            try
            {
                File.ReadAllText(Path.Combine(BlockedDir, "secret.txt"));
                notEnforcedReadFailedToBlocked = true;
            }
            catch (Exception E)
            {
                notEnforcedReadFailedToBlocked = false;
            }

            try
            {
                using var f = File.OpenWrite(Path.Combine(BlockedDir, "newfile.txt"));
                notEnforcedWriteFailedToBlocked = true;
            }
            catch (Exception E)
            {
                notEnforcedWriteFailedToBlocked = false;
            }

            try
            {
                using var f = File.OpenWrite(Path.Combine(AllowedDir, "newfile.txt"));
                notEnforcedWriteFailedToReadOnlyAllowed = true;
            }
            catch (Exception E)
            {
                notEnforcedWriteFailedToReadOnlyAllowed = false;
            }
        });

        threadWithoutLandlock.Start();
        threadWithoutLandlock.Join();

        Assert.IsTrue(notEnforcedReadFailedToBlocked,           "Reading from a blocked directory should work");
        Assert.IsTrue(notEnforcedWriteFailedToBlocked,          "Writing to a blocked directory should work");
        Assert.IsTrue(notEnforcedReadWorkedToReadOnlyAllowed,   "Reading from an read-only allowed directory should work");
        Assert.IsTrue(notEnforcedWriteFailedToReadOnlyAllowed,  "Writing to an read-only allowed directory should work");
    }
    [TestMethod]
    public void LandlockEnforcesPortRules()
    {
        if (Landlock.GetAbiVersion() < 4)
        {
            Assert.Inconclusive("TCP port rules need Landlock ABI 4 (Linux 6.7)");
        }

        using var allowed = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        using var blocked = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        allowed.Start();
        blocked.Start();

        var allowedPort = ((System.Net.IPEndPoint)allowed.LocalEndpoint).Port;
        var blockedPort = ((System.Net.IPEndPoint)blocked.LocalEndpoint).Port;

        bool connectedToAllowed = false;
        bool connectedToBlocked = false;

        var threadWithLandlock = new Thread(() =>
        {
            var sandbox = Landlock.CreateRuleset(null, new[] { Landlock.Network.CONNECT_TCP });

            sandbox.AddPortRule(allowedPort, Landlock.Network.CONNECT_TCP);
            sandbox.Enforce();

            connectedToAllowed = TryConnect(allowedPort);
            connectedToBlocked = TryConnect(blockedPort);
        });

        threadWithLandlock.Start();
        threadWithLandlock.Join();

        Assert.IsTrue(connectedToAllowed,  "Connecting to the port the rule allows should work");
        Assert.IsFalse(connectedToBlocked, "Connecting to any other port should fail");
    }

    [TestMethod]
    public void AddPortRuleRejectsAnInvalidPort()
    {
        if (Landlock.GetAbiVersion() < 4)
        {
            Assert.Inconclusive("TCP port rules need Landlock ABI 4 (Linux 6.7)");
        }

        var sandbox = Landlock.CreateRuleset(null, new[] { Landlock.Network.CONNECT_TCP });

        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() => sandbox.AddPortRule(70000, Landlock.Network.CONNECT_TCP));
    }

    private static bool TryConnect(int port)
    {
        try
        {
            using var client = new System.Net.Sockets.Socket(System.Net.Sockets.AddressFamily.InterNetwork, System.Net.Sockets.SocketType.Stream, System.Net.Sockets.ProtocolType.Tcp);
            client.Connect(System.Net.IPAddress.Loopback, port);
            return true;
        }
        catch (System.Net.Sockets.SocketException)
        {
            return false;
        }
    }
}
