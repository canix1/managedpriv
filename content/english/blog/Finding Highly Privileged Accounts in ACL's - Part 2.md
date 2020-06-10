---
title: "Finding Highly Privileged Accounts in ACL's - Part 2 - GROUP POLICY"
date: 2020-06-10T15:58:12+06:00
# meta description
description: "Detecting powerfull accounts by ACL's"
# page title background image
bg_image_webp: "images/backgrounds/page-title.webp"
bg_image: "images/backgrounds/page-title.jpg"
# post thumbnail
image: "images/blog/DefenseEvasion.webp"
image_webp: "images/blog/DefenseEvasion.jpg"
# post author
author: "Robin Granberg"
# taxonomies
categories: ["ACL",GPO,"AD ACL Scanner","Active Directory"]
tags: ["GPO","Security","Active directory","ACL","Assessment","Privileged Account"]
# type
type: "post"


---
In the previous post [Part 1](https://managedpriv.com/blog/finding-highly-privileged-accounts-in-acls-part-1/) I introduced a way to detect a malicious actor account in the access control list of the domain root. In this post I will show you how to identify persistence and privilege creep on a domain via Group Policy permissions.

Group Policies controls your environment and settings so any control over a GPO linked to a scope of management that covers any computer or user gives the attacker an extremely powerful tool and possibilities to pursue the objectives.

The most obvious locations where you should have monitoring turned on and absolute control of are:
* Domain root
* Domain Controllers organizational unit

Any accounts having control over group policies at these locations owns the domain!
These accounts are Tier 0 accounts and should be treated as the same. 

If you are not familiar with  the Tier Model and Active Directory you must read up on it.
For mor information on the Tier Model see https://aka.ms/tiermodel

### Objectives
    
* Detect defense evasion via Group Policy Modification (**MITTRE ATT&CK** [**T1484**)](https://attack.mitre.org/techniques/T1484)

* Identify gaps in the principle of least privilege **NIST** [**AC-6 (5)**](https://nvd.nist.gov/800-53/Rev4/control/AC-6)
	
### GROUP POLICY OBJECTS

Group Polices are objects in Active Directory and has access control list like all the objects in Active Directory.

What are the default permissions of a GPO you might wonder?
Here's the default permissions the group policy gets at creation, this is the value of the DefaultSecurityDescriptor attribute in the Schema of Active Directory:

~~~~
Dn: CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=contoso,DC=com
defaultSecurityDescriptor: D:P(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;DA)(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;EA)
(A;CI;RPWPCCDCLCLOLORCWOWDSDDTSW;;;CO)(A;CI;RPWPCCDCLCLORCWOWDSDDTSW;;;SY)(A;CI;RPLCLORC;;;AU)(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;CI;LCRPLORC;;;ED); 
~~~~

[ {{< image src="../../images/blog/GPOdefSD.webp" srcAlt="../../images/blog/GPOdefSD.png" >}}](../../images/blog/GPOdefSD.png "Click to zoom")


Ok, conclusions on this.
The creator of the GPO will get full control and so does the Domain Admins, Enterprise Admins and System. Authenticated users can apply and read the GPO's by default. The forests domain controllers are assured read access on new GPOs.

### ADVANCED HUNTING

Let's hunt for misconfigurations on GPO's linked to the Domain Controller OU.

To do that we add the parameter **-GPO** to [ADACLScan.ps1](https://github.com/canix1/ADACLScanner)

We want only to see critical permissions.
```powershell
.\ADACLScan.ps1 -b "OU=Domain Controllers,DC=contoso,DC=com" -GPO -Criticality Critical | ft
```

[ {{< image src="../../images/blog/GPOPermStep1.webp" srcAlt="../../images/blog/GPOPermStep1.png" >}}](../../images/blog/GPOPermStep1.png "Click to zoom")

The result contains a lot of expected permissions but also missing out an important part of the security decscriptor… The Owner.

Time to filter out expected permissions and include the owner
```powershell
.\ADACLScan.ps1 -b "OU=Domain Controllers,DC=contoso,DC=com" -GPO -Criticality Critical -SkipDefaults -SkipBuiltIn -Owner | ft
```
[ {{< image src="../../images/blog/GPOPermStep2.webp" srcAlt="../../images/blog/GPOPermStep2.png" >}}](../../images/blog/GPOPermStep2.png "Click to zoom")

We just identified an attempted Defense Evasion (**MITTRE ATT&CK ID**:[**T1484**](https://attack.mitre.org/techniques/T1484/)).

The account **CONTOSO\APT29** can perform malicious GPO modifications like Scheduled Task, Disabling Security Tools, Remote File Copy, Create Account, Service Execution and more.

#### Remediation action
Replace the owner on **WSUS Patch Schedule 1** with Domain Admins.

Let us continue analyzing the ACL.

**WSUS Admins** is a group and we need to know what accounts are members and the nested groups. Add **-RecursiveFind** to the command.

```powershell
.\ADACLScan.ps1 -b "OU=Domain Controllers,DC=contoso,DC=com" -GPO -Criticality Critical -SkipDefaults -SkipBuiltIn -Owner  -RecursiveFind | ft
```

[ {{< image src="../../images/blog/GPOPermStep3.webp" srcAlt="../../images/blog/GPOPermStep3.png" >}}](../../images/blog/GPOPermStep3.png "Click to zoom")


We got two admins, **Alice** and **Bob**, but who is **joe**?

[ {{< image src="../../images/blog/GPOPermStep4.webp" srcAlt="../../images/blog/GPOPermStep4.png" >}}](../../images/blog/GPOPermStep4.png "Click to zoom")

It is our disgruntled employee Joe! There is a risk that Joe might take retaliatory actions by disrupting the business or stealing information.

Joe is a member of the **SCCM Admins** that are nested in to the **WSUS Admins** group.
We do not consider the **SCCM Admins** as "Tier 0" admins and it should not have control over Domain Controllers.

What we got here is an example of privilege creep. We are not enforcing the principle of least-privilege **NIST** [**AC-6 (5)**](https://nvd.nist.gov/800-53/Rev4/control/AC-6) and we should look into our access management process to identify the gap in the process that led to this problem.

#### Remediation action
1. Remove **SCCM Admins** from **WSUS Admins**.
2. Monitor for security group managent events in the security log on the domain controllers.

### DETECTION
Besides assessing your GPO's ACL, you should monitor for changes to group policy objects and privileged groups. Here's some examples of security events that are generated in your domain controller’s security log.

#### 4662 - Audit Success - Directory Service Access
Changing permissions on a group policy object 

|   4662	|   An operation was performed on an object.	|
|---	|---	|
|**Subject:**|
|Security ID:	|CONTOSO\administrator|
|Account Name:	|Administrator|
|Account Domain:|CONTOSO|
|Logon ID:|0x1D144B7|
|**Object:**|
|Object Server:|DS|
|Object Type:|groupPolicyContainer|
|Object Name:|CN={43708369-9B79-4035-AB85-94365CA23621},CN=Policies,CN=System,DC=contoso,DC=com|
|Handle ID:|0x0|
|**Operation:**|
|Operation Type:|Object Access|
|Accesses:|WRITE_DAC|
|Access Mask:|0x40000|
|Properties:|WRITE_DAC	{f30e3bc2-9ff0-11d1-b603-0000f80367c1}|
|**Additional Information:**|
|Parameter 1:|-|
|Parameter 2:||

#### 5136 - Audit Success - Directory Changes
Modifying the security descriptor on a group policy object. This one is followed up with a Type: Value Deleted event.

|   5136	|   A directory service object was modified.	|
|---	|---	|
|**Subject:**|
|Security ID:	|CONTOSO\administrator|
|Account Name:	|Administrator|
|Account Domain:|CONTOSO|
|Logon ID:|0x1FD9905|
|**Directory Service:**|
|Name:|contoso.com|
|Type:|Active Directory Domain Services|
|**Object:**|
|DN:|cn={43708369-9B79-4035-AB85-94365CA23621},cn=policies,cn=system,DC=contoso,DC=com|
|GUID:|CN={43708369-9B79-4035-AB85-94365CA23621},CN=Policies,CN=System,DC=contoso,DC=com|
|Class:|groupPolicyContainer|
|**Attribute:**|
|LDAP Display Name:|nTSecurityDescriptor|
|Syntax (OID):|2.5.5.15|
|Value::|O:DAG:DAD:PAI(OA;CI;CR;edacfd8f-ffb3-11d1-b41d-00a0c968f939;;AU)(A;;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;CCDCLCRPWPSDRCWDWO;;;S-1-5-21-2790215031-3985095115-3368729028-3611)(A;CI;CCDCLCRPWPSDRCWDWO;;;S-1-5-21-2790215031-3985095115-3368729028-3612)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;DA)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;S-1-5-21-2790215031-3985095115-3368729028-519)(A;CI;LCRPLORC;;;ED)(A;CI;LCRPLORC;;;AU)(A;CI;CCDCLCSWRPWPDTLOSDRCWDWO;;;SY)(A;CIIO;CCDCLCSWRPWPDTLOSDRCWDWO;;;CO)S:AI(OU;CIIDSA;WPWD;;f30e3bc2-9ff0-11d1-b603-0000f80367c1;WD)(OU;CIIOIDSA;WP;f30e3bbe-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)(OU;CIIOIDSA;WP;f30e3bbf-9ff0-11d1-b603-0000f80367c1;bf967aa5-0de6-11d0-a285-00aa003049e2;WD)|
|**Operation:**|
|Type:|Value Added|
|Correlation ID:|{33bbb60c-6de6-4edc-8408-65ff1f1319b9}|
|Application Correlation ID:|-|

#### 4728 - Audit Success - Security Group Management
Adding a member to a global security group.

|   4728	|   A member was added to a security-enabled global group.	|
|---	|---	|
|**Subject:**|
|Security ID:	|CONTOSO\administrator|
|Account Name:	|Administrator|
|Account Domain:|CONTOSO|
|Logon ID:|0x1FD9905|
|**Member:**|
|Security ID:|CONTOSO\SCCM Admins|
|Account Name:|CN=SCCM Admins,OU=CORP,DC=contoso,DC=com|
|**Group:**|
|Security ID:|CONTOSO\WSUS Admins|
|Group Name:|WSUS Admins|
|Group Domain:|CONTOSO|
|**Additional Information:**|
|Privileges:|-|

### Summary 

We identified two examples of misconfiguration's in the security descriptor on group policy objects. 

First, we identified the persistence created with the account **CONTOSO\APT29**. Where the adversaries tried to maintain access, with the intention of escalating privileges on the domain and avoid detection throughout their compromise. The problem was the incorrect ownership in the security descriptor on a GPO linked to the domain controller OU.

Secondly, we identified the privilege creep created by inappropriate nesting of security groups. The user **joe**, a disgruntled employee, had unintentional control over the domain controllers. 

#### Conclusion
Create a clear picture of your current security posture and make sure your SIEM create incidents for modifications of sensitive ACL's and groups.