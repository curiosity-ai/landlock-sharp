# Landlock for .NET

*A lightweight C# wrapper for the (https://landlock.io/)[Linux Landlock kernel sandboxing feature].*

[![NuGet](https://img.shields.io/nuget/v/Landlock.svg)](https://www.nuget.org/packages/Landlock)

## 📦 Installation

Add the NuGet package:

```bash
dotnet add package Landlock
```

Or visit: [https://www.nuget.org/packages/Landlock](https://www.nuget.org/packages/Landlock)

---

## 🔍 What is Landlock?

Landlock is a Linux kernel security feature (available since Linux 5.13) that lets unprivileged applications restrict their own filesystem access using an allow-list model. Once a ruleset is enforced, the process—and any child processes—can only access explicitly permitted paths, providing simple but effective sandboxing without requiring root privileges or system-wide configuration.

---

## 📌 Library Overview

This library provides a clean and idiomatic C# interface for working with Landlock, allowing you to define filesystem rulesets, grant specific directory or file permissions, and enforce permanent access restrictions at runtime. It is intended for sandboxing plugins, securing file operations, or adding defense-in-depth to applications running on Linux.

---

## 🛠️ Usage

```csharp
using Landlock;

var supported = Landlock.IsSupported();

if (supported)
{
    var sandbox = Landlock.CreateRuleset(Landlock.FileSystem.CORE);

    sandbox.AddPathBeneathRule(
        AllowedDir,
        Landlock.FileSystem.READ_FILE,
        Landlock.FileSystem.READ_DIR
    );

    sandbox.Enforce();
}
```

This example checks for kernel support, creates a ruleset controlling core filesystem operations, allows read access to a specific directory, and enforces the sandbox so the process cannot access anything outside the allowed paths.

---

## 🧪 Requirements

* Linux kernel 5.13+
* .NET 6.0+
* No root privileges required

---

## 📝 License

MIT License.