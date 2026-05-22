---
title: "The Hidden Traps in ActiveDirectorySecurity Class"
date: 2026-05-22T10:00:00+00:00
description: "Why the .NET ActiveDirectorySecurity API is fundamentally unsuitable for ACL backup, restore, migration, and any tooling that requires bit-perfect fidelity."
bg_image_webp: "images/backgrounds/page-title.webp"
bg_image: "images/backgrounds/page-title.jpg"
image: "images/blog/ActiveDirectorySecurityClass.webp"
image_webp: "images/blog/ActiveDirectorySecurityClass.png"
author: "Robin Granberg"
categories: ["Active Directory Coding","ACL","Security"]
tags: ["Active Directory","ACL","Security Descriptor","PowerShell","RawSecurityDescriptor","ActiveDirectorySecurity"]
type: "post"
---

If you have ever tried to build an ACL backup tool, a delegation cloning script, or a migration utility for Active Directory using the standard .NET `System.DirectoryServices` classes, you have probably run into mysterious bugs where permissions come back subtly different after a roundtrip, inheritance flags change without explanation, or certain ACEs simply vanish.

This is not a bug in your code. It is a fundamental design problem in the API itself.

This post covers what those problems are, why they exist, and what you should use instead.

## Background: What the API Was Designed For

`System.DirectoryServices.ActiveDirectorySecurity`, `ActiveDirectoryAccessRule`, `ActiveDirectoryAuditRule`, and `ActiveDirectorySecurityInheritance` were introduced around the .NET 2.0 era — roughly Windows Server 2003 time — as a managed wrapper on top of the older ADSI (Active Directory Service Interfaces) COM APIs.

The design goal was administrative simplicity: make it easy to write helpdesk scripts, power the delegation wizard in Active Directory Users and Computers, and let administrators add common permissions without needing to understand the underlying binary security descriptor format.

That goal was achieved. For simple administration, the API works fine.

The problem is that the API was **never designed for fidelity**. It was designed for convenience. When you try to use it for:

- Exact ACL backup and restore
- Migration tooling
- Delegation cloning
- Forensic analysis
- Security diffing

...it starts to fall apart, because every layer of the API makes lossy transformations to the underlying ACE data.

## The Real Model vs the .NET Model

Before listing the specific problems, it helps to understand what AD actually stores.

An ACE in Active Directory is a binary structure with these fields:

``` 

ACE_HEADER                  (type, flags)
ACE_FLAGS                   (inheritance and propagation bitmask)
ACCESS_MASK                 (what rights are granted or denied)
SID                         (who the ACE applies to)
OBJECT_TYPE_GUID            (optional: which object class or extended right)
INHERITED_OBJECT_TYPE_GUID  (optional: which object class can inherit)

```

That is the real model. What .NET presents to you is an abstraction on top of it:

```csharp
ActiveDirectoryAccessRule 
  .InheritanceType    // enum: None, All, Descendents, Children, SelfAndChildren
  .PropagationFlags   // flags: None, NoPropagateInherit, InheritOnly
  .InheritanceFlags   // flags: None, ContainerInherit, ObjectInherit
```

The `InheritanceType` enum is not a real AD attribute. It is a .NET invention that tries to map the underlying `AceFlags` bitmask — which contains `OBJECT_INHERIT_ACE`, `CONTAINER_INHERIT_ACE`, `INHERIT_ONLY_ACE`, and `NO_PROPAGATE_INHERIT_ACE` — into a handful of named constants.

That mapping is lossy and not always reversible.

## Design Problem 1: ActiveDirectorySecurityInheritance Is Not Reversible

This is the most impactful problem.

The `ActiveDirectorySecurityInheritance` enum tries to abstract `AceFlags` into:

| Enum value | Intended meaning |
|---|---|
| `None` | This object only |
| `All` | This object and all descendants |
| `Descendents` | Descendants only |
| `Children` | Direct children only |
| `SelfAndChildren` | This object and direct children |

The problem is that several different `AceFlags` combinations map to the same enum value, making the mapping non-reversible. The round-trip:

```
ACE flags → InheritanceType enum → ACE flags
```

is **not stable**. You feed in one set of flags, get an enum value, reconstruct from that enum value, and come out with different flags than what you started with.

A concrete example: an ACE with `InheritanceFlags = ContainerInherit` and `PropagationFlags = None` gets mapped to `Children`, but when reconstructed from `Children`, the result uses `NoPropagateInherit + InheritOnly` — which has completely different semantics.

## Design Problem 2: AddAccessRule() Mutates Your ACEs

This is the most dangerous problem for anyone writing restore or templating tools.

When you call:

```powershell
$sec.AddAccessRule($ace)
```

you are not just appending an ACE to the ACL. The method:

- **Merges** ACEs that it considers equivalent
- **Rewrites** `AceFlags`
- **Reorders** the ACL (canonicalization)
- **Absorbs** rights that are already covered by a broader ACE
- **Translates** inheritance flags through the lossy enum layer

For example: if an object already has a `GenericAll` ACE for a principal, adding a `CreateChild` ACE for the same principal may result in the new ACE being silently discarded, because `.NET` considers it already covered.

The ACL you wrote is not the ACL you get back.

## Design Problem 3: PropagationFlags Are Silently Changed

`PropagationFlags` controls how inheritance propagates down the tree:

- `NoPropagateInherit` — do not pass the ACE to children's children
- `InheritOnly` — the ACE does not apply to the object itself, only to children

When you construct an `ActiveDirectoryAccessRule` with specific `PropagationFlags` and write it through `AddAccessRule()`, these flags are often:

- Dropped entirely
- Changed during the inheritance enum conversion
- Reinterpreted based on the `InheritanceType` value

This is particularly damaging for tools that need to precisely reproduce delegations that use `InheritOnly` — for example, ACEs that apply only to child objects of a specific class without applying to the parent OU.

## Design Problem 4: GetAccessRules() Does Not Return Raw ACEs

When you read ACEs back with:

```powershell
$sec.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
```

you receive `ActiveDirectoryAccessRule` objects, not the underlying `CommonAce` or `ObjectAce` objects. The conversion back from binary to the .NET model applies the same lossy transformations described above.

So even a pure read — no write — loses information. You cannot use `GetAccessRules()` as a faithful representation of what AD actually stores.

## Design Problem 5: Object ACE Flags Can Disappear

Object-specific ACEs — those that reference a specific object class (like `computer`) or an extended right (like `User-Force-Change-Password`) — use an `ObjectAceFlags` bitmask:

- `ObjectAceTypePresent` — the `ObjectType` GUID is meaningful
- `InheritedObjectAceTypePresent` — the `InheritedObjectType` GUID is meaningful

When either GUID is `Guid.Empty`, the corresponding flag should be cleared. But `ActiveDirectoryAccessRule` sometimes clears these flags incorrectly, or fails to set them correctly on construction, which results in:

- Object-specific ACEs being misread as generic ACEs
- GUIDs being ignored even when present
- ACE semantics silently changing

## Design Problem 6: RemoveAccessRuleSpecific() Is Not Always Specific

The name implies exact matching, but the implementation compares ACEs using .NET's abstracted representation rather than the raw binary form. This means:

- An ACE with unusual `PropagationFlags` may not be found and removed
- The method may match the wrong ACE if two ACEs differ only in flags that the abstraction layer treats as equivalent
- Removal can silently fail with no error

## Design Problem 7: Audit ACEs Are Even Worse

`ActiveDirectoryAuditRule` and the SACL handling in `ActiveDirectoryAuditRuleSpecific` have all the same problems as the DACL handling, plus additional issues:

- Audit flag combinations are more aggressively normalized
- The SACL is more likely to be rewritten on commit
- Propagation flags for audit ACEs are frequently dropped

## Design Problem 8: AD Itself May Rewrite ACEs

This is not just a .NET problem. When you submit a security descriptor to AD via LDAP, the LSASS canonicalizer on the domain controller may:

- Reorder ACEs to enforce canonical order
- Transform certain inheritance combinations
- Reject non-standard ACEs

This means even a raw binary restore of a security descriptor is not always guaranteed to produce an identical result on the server side. The practical impact varies significantly between domain functional levels and Windows Server versions.

## Design Problem 9: Historical Context — Maintenance Mode Since .NET 3.5

`System.DirectoryServices` has received almost no functional improvements since the .NET 3.5 era. The API predates many modern AD features:

- Fine-grained password policies
- Dynamic access control / conditional ACEs
- Callback ACEs
- Modern extended rights introduced in later schema versions

The .NET Framework 4.8 and the NuGet packaging of `System.DirectoryServices` for modern .NET are largely compatibility layers. The underlying implementation has not been substantially updated to match the richness of the current AD security model.

The Microsoft documentation itself recommends using `RawSecurityDescriptor` for scenarios requiring fidelity.

## The Correct Approach: RawSecurityDescriptor

If you need any of the following:

- Bit-perfect ACE restore
- Exact inheritance preservation
- Exact propagation flags
- Correct object ACE handling
- Stable export/import roundtrip

...you must work directly with:

```powershell
$rawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor($sdBytes, 0)
foreach ($ace in $rawSD.DiscretionaryAcl) {
    [PSCustomObject]@{
        Identity    = $ace.SecurityIdentifier.Value
        Rights      = try {
                          ([System.DirectoryServices.ActiveDirectoryRights]$ace.AccessMask).ToString()
                      } catch { $ace.AccessMask }
        AceType     = $ace.AceType
        AceFlags    = $ace.AceFlags
        ObjectAceType = if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                            $ace.ObjectAceType
                        }
        InheritedObjectAceType = if ($ace -is [System.Security.AccessControl.ObjectAce]) {
                            $ace.InheritedObjectAceType
                        }
    }
}
```

Key points:

- `RawSecurityDescriptor` parses the binary security descriptor without any transformation
- `ObjectAce` represents ACEs that carry one or both GUIDs (object type, inherited object type)
- `CommonAce` represents ACEs without GUIDs
- `AceFlags` gives you the raw `OBJECT_INHERIT_ACE`, `CONTAINER_INHERIT_ACE`, `INHERIT_ONLY_ACE`, `NO_PROPAGATE_INHERIT_ACE` bitmask directly
- The only AD-specific enum you typically need is `[System.DirectoryServices.ActiveDirectoryRights]` — and only for human-readable output, not for logic

Note that `RawAcl.InsertAce()` performs **no canonicalization** — it is simple list insertion. This is exactly what you want for restore operations.

## When Is Each API Appropriate?

| Use case | API |
|---|---|
| Helpdesk delegation | `ActiveDirectoryAccessRule` — fine |
| ADUC-style administration | `ActiveDirectoryAccessRule` — fine |
| ACL backup / restore | `RawSecurityDescriptor` + `RawAcl` |
| Migration tooling | `RawSecurityDescriptor` + `RawAcl` |
| Exact delegation clone | `RawSecurityDescriptor` + `RawAcl` |
| ACL diffing / auditing | `RawSecurityDescriptor` + `RawAcl` |
| Security tooling / attack path | `RawSecurityDescriptor` + `RawAcl` |

## Summary

`System.DirectoryServices.ActiveDirectorySecurity` was built for administrative convenience in the early 2000s and has not evolved significantly since then. It introduces silent, lossy transformations at every layer: when reading ACEs, when constructing `ActiveDirectoryAccessRule` objects, when calling `AddAccessRule()`, and when interpreting `ActiveDirectorySecurityInheritance`.

For any tooling where the exact binary representation of an ACE matters — backup, restore, migration, diffing, forensic analysis — the only reliable path is `RawSecurityDescriptor`, `RawAcl`, `ObjectAce`, and `CommonAce`, using the AD rights enum only for display purposes.

The irony is that `RawSecurityDescriptor` is actually simpler to reason about once you understand the underlying ACE structure, because it does exactly what you tell it and nothing more.

---

*The next post in this series covers canonical ACL ordering — what it is, why it matters for security, and what happens when you write a non-canonical ACL to Active Directory.*
