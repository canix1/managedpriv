    ---
title: "Exposing Azure AD Roles with privileged access groups"
date: 2021-02-12T12:45:32+06:00
# meta description
description: "Explains how privileged access can introduce a new attack path"
# page title background image
bg_image_webp: "images/backgrounds/page-title.webp"
bg_image: "images/backgrounds/page-title.jpg"
# post thumbnail
image: "images/blog/PIMAdmin.webp"
image_webp: "images/blog/PIMAdmin.jpg"
# post author
author: "Robin Granberg"
# taxonomies
categories: ["Privilege Identity Management","Azure AD"]
tags: ["Azure AD","Privilege Access","PIM"]
# type
type: "post"


---
In this article I will dig into the possible ways of adding memberships in roles and groups in Azure AD and Azure resources. I will especially focus on when you can use the just-in-time privilege access feature in Privilege Identity Management (PIM). With the preview function Privileged access groups there is more opportunities to make use of the awesome features of PIM. I will discuss a couple of scenarios where this might not be such a good idea.

### Privilege access groups
Privileged access groups is a cool feature that allows you to create new groups that are protected from normal group management i.e. only **Global Administrator** and **Privileged Role Administrator** can managed the members. You also get the same role settings like Azure AD roles have.  

But there is a big difference! These groups have owners that can manage the group, but the owners do not have to be a member of any privileged group at all.   

These Azure AD groups are either security groups or Microsoft 365 groups, that have been enabled for **Azure AD roles can be assigned to the group**. What happens is that the group get its property **isAssignableToRole** set  to **true**.  You can only enable this feature while creating the group.

##### PowerShell example  
Creating a Microsoft 365 group that is assignable to roles.
```powershell
New-AzureADMSGroup -DisplayName "AAD M365 Group /w AAD Role" -Description "This group is assigned to Helpdesk Administrator built-in role in Azure AD." -MailEnabled $true -SecurityEnabled $true -MailNickName "AADM365Group/wAADRole" -IsAssignableToRole $true
```   

| Note: Your PIM instance must have been upgraded to support privileged access groups.  | 
| ----------- |   


Small extract of properties of a group with **isAssignableToRole: true**  

```
{
"id": "909fdafa-1b1f-4ce3-8258-fba999a24ff9",  
"deletedDateTime": null,  
"classification": null,  
"createdDateTime": "2020-10-27T12:16:02Z",  
"creationOptions": [],  
"description": null,  
"displayName": "AAD M365 Group /w AAD Role",
"expirationDateTime": null,  
"groupTypes": [],  
"isAssignableToRole": true,  
}
```  
You cannot change this value after the group is created since its immutable.
If you try to change this value for an existing group, you will get this error:  
`Value for IsAssignableToRole cannot be updated for groups assignable to role. `

There is a maximum number of **251** for role-assignable groups per Azure AD tenant.  

When an Azure AD group is enabled for privileged access management you can manage the members or the owners through PIM and select between active or eligible access.

#### Member types
There are three states in which an object can be member of a group in a scenario where PIM has been deployed. These are the three different states:

**Eligible**  -  The member has to take actions to activate the privilege access.  

**Active**  -  The member doesn’t need to perform any action to active the privilege access. 

**Direct membership**  -  This means that the member has been added to the group or role outside of PIM. PIM cannot manage the membership with just-in-time access. This type of membership is either Assigned or Dynamic.

What different objects can have members in Azure you might ask?

Objects that can have members:
* Azure AD Roles
* Azure AD Custom Roles
* Azure AD Security Group
* Azure AD Security Group Synced
* Azure AD Microsoft 365 Group
* Azure Roles
* Azure Custom Roles


### Membership by object type
Below is a matrix of the different memberships that can take place in Azure and through PIM.
I have found that Azure AD Custom Roles and Azure Custom Roles behave the same as built in roles so custom roles do not have an own column.  

Column headings represent the objects that can have members. Table rows contain the objects that are potential members.


| Possible member        | AAD Role      | Az Role  | AAD Security Group  | *AAD Security Group /W AAD Roles  | AAD M365 Group | *AAD M365 Group /W AAD Roles|Synced Group|
| ------------- |:-------------:| -----:| -----:| -----:| -----:| -----:| -----:|
| User                        |    P |    P |    D |    P |    P |    P |    - |
| Synced User                 |    P |    P |    D |    P |    P |    P |    D |
| AAD Role                    | -    |    - |    - |    - |    - |    - |    - |
| AZ Role                     |    - |    - |    - |    - |    - |    - |    - |
| ADD Security Group                   |    - |    P |    D |    P |    - |    P |    - |
| AAD Security Group /W AAD Roles       |    P |    P |    D |    P |    - |    P |    - |
| AAD M365 Group              |    - |    P |    D |    P |    - |    P |    - |
| AAD M365 Group /W AAD Roles  |    P |    P |    D |    P |    - |    P |    - |
| Synced Group                |    - |    P |    D |    P |    - |    P |    - |

* P = Active/eligible assignment possible with PIM
* D = Direct member only, PIM not supported
* \- = Cannot be a member
* \* =  **\/W AAD Roles**  is the *Azure AD roles can be assigned to the group* setting that enables an Azure AD group for privilege access. This is a preview feature at the time of writing.

#### Nesting scenario

Microsoft suggest some scenarios in the article [Management capabilities for privileged access Azure AD groups (preview)]( https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features) about privileged access groups  

|{{< image src="../../images/blog/PIMNesting2.webp" srcAlt="../../images/blog/PIMNesting2.png" >}}|
| ------ |

### Visibility Lost
Even though this is a totally legitimate scenario it might not be the best option from a security perspective…   

Why?  

**Azure AD Privilege Identity Manager has lost visibility in who has role memberships.**  

Bellow you can see that PIM tells you that **Global Administrator** has 1 eligible and 1 active member.  

| {{< image src="../../images/blog/PIMNesting3.webp" srcAlt="../../images/blog/PIMNesting3.png" >}}|
| ------ |



**This is not true!**  

There are in fact **4** **Global Administrator**'s.  

1 permanent account and 3 eligible accounts.

Let us go through why.

The account **myga** is a permanent member of **Global Administrator**, which is visualized by PIM’s dashboard.

|{{< image src="../../images/blog/PIMNesting5.webp" srcAlt="../../images/blog/PIMNesting5.png" >}}|
| ------ |  


**Global Administrator** has also an “IsAssignableToRole”-enabled group called **AAD Security Group /w AAD Role** as eligible member, which is also visualized by PIM’s dashboard.  

|{{< image src="../../images/blog/PIMNesting4.webp" srcAlt="../../images/blog/PIMNesting4.png" >}}|
| ------ |   

When we examine the members of **AAD Security Group /w AAD Role** we see that is has a standard security group as eligible member.  

This is where PIM lost it.  
The nesting is not calculated in the PIM dashboard.

|{{< image src="../../images/blog/PIMNesting6.webp" srcAlt="../../images/blog/PIMNesting6.png" >}}|
| ------ |   

And if we look at the group **AAD Security Group** we see it has three direct members. Also not calculated by the PIM dashboard.

|{{< image src="../../images/blog/PIMNesting7.webp" srcAlt="../../images/blog/PIMNesting7.png" >}}|
| ------ |   


### Possible Attack Path  

When you create complex schemes for you privileged access you might lose insight and control on "who can do what".  

|{{< image src="../../images/blog/PIMNesting1.webp" srcAlt="../../images/blog/PIMNesting1.png" >}}|
| ------ |   
   

If Anna is made owner for **AAD Security Group** or if she would be **Group Administrator**, she could add members to **AAD Security Group**. Any Member of **AAD Security Group** can activate access to **AAD Security Group /W AAD Role**.   
  

Let say Anna put her own account in to this group in **AAD Security Group** and activate **AAD Security Group /W AAD Role** in PIM.  

Now she can activate the **Global Administrator** role since **AAD Security Group /W AAD Role** is eligible to it.

#### Possible Attack Path  - Example
Needless to say, we expose the highly privileged roles managed by PIM in a new way when nesting with privileged access groups or standard groups for that matter too.  

Exposure araises from the fact that:
* \- Owner of a privilged access group or standard group..
    * \- does not follow the role requirements or process in PIM
    * \- does not require any privilged group

* \- Nesting groups in roles moves the control to other admins outside of PIM

  
I draw a simple [Bloodhound](https://github.com/BloodHoundAD/BloodHound)-like attack graph bellow go give you an example of control paths that exist. This picture is far from the full graph of possible attack paths.

|{{< image src="../../images/blog/PIMNesting8.webp" srcAlt="../../images/blog/PIMNesting8.png" >}}|
| ------ |   


#### Conclusion

It is crucial that administrators understand all the ways to control objects and how the tools work. Because if they don't , they might introduce new weaknesses in the design.

Here are a few things to consider into your design:

*  nesting groups in roles make PIM loose visibility
*  nesting groups in roles moves the control to other admins outside of PIM
*  privileged access groups can be nested
*  privileged access groups have owners
*  if synced groups are nested in to privileged access groups or Azure roles the control is moved to on-premise Active Directory



#### References

Use cloud groups to manage role assignments in Azure Active Directory (preview)  
https://docs.microsoft.com/en-us/azure/active-directory/roles/groups-concept  

Management capabilities for privileged access Azure AD groups (preview)
https://docs.microsoft.com/en-us/azure/active-directory/privileged-identity-management/groups-features

BloodHound  
https://github.com/BloodHoundAD/BloodHound
