    ---
title: "Breaching the sensitive action zone in Entra ID PIM"
date: 2024-04-13T12:45:32+06:00
# meta description
description: "Getting diffrent properties depending on your authentcation"
# page title background image
bg_image_webp: "images/backgrounds/page-title.webp"
bg_image: "images/backgrounds/page-title.jpg"
# post thumbnail
image: "images/blog/Security_Zone_Sensitive_Actions.webp"
image_webp: "images/blog/Security_Zone_Sensitive_Actions.jpg"
# post author
author: "Robin Granberg"
# taxonomies
categories: ["Privilege Identity Management","Azure AD"]
tags: ["Entra ID","API"]
# type
type: "post"


---

Entra ID PIM is a great security tool if used correctly. But I often see how it's not well configured. That makes me sad when an organization has the opportunity to improve its security posture, but lacks the insight or knowledge of the potential protection available or even lives in a false sense of protection.

The most critical accounts in the tenant must be protected at all costs, the security risk on these accounts is inherited down on all other resources and services in the tenant.

Back in 2021, I wrote the blog post [**Exposing Azure AD Roles with privileged access groups**](https://managedpriv.com/blog/azure-ad-group-nesting) where I identified the possibility of nesting a standard security group in a role assignable group. 
After that, I reached out to the Microsoft Security Response Center to inform them about this breach in privileged security zones.

In this post, I would like to highlight and re-iterate the problem I see and show you how to use the tool [**PIMSCAN**](https://github.com/canix1/PIMSCAN) to identify the problem, which is not trivial using the portal.

What do I mean by a breach in a privileged security zone?

There are actions in Entra ID identity management that are classified as "sensitive actions" https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions?tabs=admin-center#who-can-perform-sensitive-actions

In short the following situations only **Privileged Auth Admin** and **Global Admin** can manage the sensitive actions as a protection from privileged escalation. See table below:

|Role that sensitive action can be performed upon|Auth Admin|User Admin|Privileged Auth Admin|Global Admin|
|----|----|----|----|----|
|Global Admin|  |   |   ✅   |✅  |
|Privileged Auth Admin| |   |   ✅   |✅  |
|Privileged Role Admin| |   |   ✅   |✅  |
|User (no admin role, but member or owner of a role-assignable group)|  |   |   ✅   |✅  |
|User with a role scoped to a restricted management administrative unit|    |   |   ✅   |✅  |
|All custom roles|  |   |   ✅   |✅  |

Table from: [Privileged roles and permissions in Microsoft Entra ID (preview)](https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions?tabs=admin-center#who-can-perform-sensitive-actions)

In my opinion, this is a sort of privileged access security zone created around the principals that are classified in the filtered table above.

This is the zone that could have exposure to non-members of **Privileged Auth Admin** and **Global Admin**.

The reason is already mentioned in my previous blog post but I will further clarify the situation and explain how it can be abused.

The introduction of role-assignable groups was a long-requested feature to simplify the management of role assignments.

The following picture shows that a security group, if created as a role-assignable group (**isRoleAssigngable=True**), can be either eligible or active in a role and the group is protected in the sensitive actions - zone.

[{{< image src="../../images/blog/sensitiveactionszone.webp" srcAlt="../../images/blog/sensitiveactionszone.png" >}}](https://managedpriv.com/images/blog/sensitiveactionszone.png) 

While introducing the option of creating groups that can be assigned to a role, it was not supposed to be able to nest standard groups into role-assignable groups.

It is not possible with one exception. A standard group can be eligible for a role-assignable group.

This means that members of the standard group can activate membership in the role-assignable group.

## Tyranny of the default

There are a couple of settings in Entra ID that have an impact on this scenario.

The settings are the following:

|Setting|Tenant Global|Value|The Default Value|
|----|----|----|----|
|Owern Self Management|Yes|Yes|Yes|
|PIM Role - Approval required|No (per role)|No|No|
|PIM Group - Approval required|No (per group)|No|No|

#### Owern Self Management
An owner of a group can manage the membership of the group.

#### PIM Role Approval Requirement
All roles have a role policy settings that by default do not have an approver. In my opinion it would have been great if the Global Administrators where the default approvers until it was change to another group or user.

#### PIM Group Approval Requirement
All groups have two role policy settings, one for members and one for owners, that by default do not have an approver. 

The default settings mean there is no actual protection from getting access to any role unless the role settings have been modified.
PIM is just providing temporary access at most in this situation for 8 hours.
An attacker that has made an account take-over has no limitations in abusing the assigned roles, active or eligible.

## ATTACK PATH

The combination of the default settings and making a standard security group eligible is a risky combination, that creates an exposure for the elevation of privileges.
This situation makes the security zone around sensitive actions exposed to less privileged security principals.

Here is a list of edges in the attack path:
|Edge|Steps|Action|
|----|----|----|
|isMember|2|Elevate to isRoleAssignabelGroup -> Elevate to role|
|isOwner|3|Make itself a member of the group -> Elevate to isRoleAssignabelGroup -> Elevate to role|
|Has Add_Member|3|Make itself a member of the group -> Elevate to isRoleAssignabelGroup -> Elevate to role|
|Has Add_Owner|3|Make itself a member of the group -> Elevate to isRoleAssignabelGroup -> Elevate to role|

The permissions Add_Member or Add_Owner is pretty common.

Here is the attack path visualized:

[{{< image src="../../images/blog/sensitiveactionszoneboken.webp" srcAlt="../../images/blog/sensitiveactionszoneboken.png" >}}](https://managedpriv.com/images/blog/sensitiveactionszoneboken.png) 

## MSRC

I reported this issue to the Microsoft Security Response Center (MSRC) in November 2023.

The response from Microsoft Security Response Center (MSRC) on the 23rd of November in 2023 was the following:

Quote MRSC:

"We determined that this behavior is considered to be by design."

I guess this means this attack vector will remain open and the organization needs to turn on approval flows to keep it in control or move the standard security group to a restricted management administration unit.

## PIMSCAN

Introducing the PowerShell tool [**PIMSCAN**](https://github.com/canix1/PIMSCAN).

[{{< image src="../../images/blog/PIMSCAN_cli.webp" srcAlt="../../images/blog/PIMSCAN_cli.png" >}}](https://managedpriv.com/images/blog/PIMSCAN_cli.png) 

By using the tool [**PIMSCAN**](https://github.com/canix1/PIMSCAN) you can unfold the nesting and identify the breach of the sensitive actions security zone.

The tool is located in my GitHub repo: 

https://github.com/canix1/PIMSCAN

The purpose of the tool is to give users a better understanding of the role assignment. 

To identify the scenario described above, look for nested groups where **Priv Mgmt** is **false**. 

When **Priv Mgmt** is **false**, it means the object can be managed by other than members of **Privileged Auth Admin** and **Global Admin**.

Here is an example of the role **Global Administrator** having a nested standard security group called **Entra ID Sec Group1** and it's a member and an owner.

[{{< image src="../../images/blog/PIMSCAN_Warning.webp" srcAlt="../../images/blog/PIMSCAN_Warning.png" >}}](https://managedpriv.com/images/blog/PIMSCAN_Warning.png) 

## Recommendation

If you are using Microsoft Entra ID PIM, be aware of that there is no protection from abuse unless you have defined an approver on the role or nested role-assignable group.

I strongly recommend that all roles be configured with approvers.

Do not make a standard group eligible to a role-assignable group that is active or eligible for a role. This is breaking the sensitive action protection implemented by Microsoft.

If you must use a standard security group as eligible for a role-assignable group, put the standard security group in a restricted management administration unit.

Make sure all role activations require Azure MFA

Regularly review role assignments, active and eligible

Regularly review the approvers, you don't want to require approval without an approver.

Monitor Entra ID PIM for strange behaviors.


