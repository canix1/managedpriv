---
title: "Do You Allow Blank Passwords In Your Environment"
date: 2019-02-07T10:47:55+06:00
# meta description
description: "this is meta description for blog page."
# page title background image
bg_image_webp: "images/backgrounds/page-title.webp"
bg_image: "images/backgrounds/page-title.jpg"
# post thumbnail
image: "images/blog/post-1.webp"
image_webp: "images/blog/post-1.jpg"
# post author
author: "Robin Granberg"
# taxonomies
categories: ["passwords"]
tags: ["security","active directory","password"]
# type
type: "post"


---

This is a repost of my previous post at: https://docs.microsoft.com/en-us/archive/blogs/pfesweplat/do-you-allow-blank-passwords-in-your-domain. My blog posts at Microsoft was temporarly deleted so just in case I re-post this one here.
<!--more-->

Do you or did you back in the days use your own code or a third party tool to create user accounts that did not update the userAccountControl attribute after the account was created? 
Well then there's a change you might have accounts in your domain that are allowed blank passwords or even worse have accounts with blank passwords!
 <!--more-->
Why! Because user objects are allowed blank passwords by default when created, something that must be handle afterwards. Unless that's in line with your security policy ;) 
 <!--more-->

This is the default setting of userAccountControl at user object creation:
userAccountControl: 0x222 = (**ACCOUNTDISABLE | PASSWD_NOTREQD | NORMAL_ACCOUNT**);
 <!--more-->

## How does this setting affect my environment?
<!--more-->

**Q:** We have a password policy in our domain that does not allow blank passwords, are we protected from blank passwords?
 <!--more-->

**A:** No, this setting overrides the password policy in the domain or your fine grained password policy when you do **reset password** operations.
<!--more-->
 
So when is the "blank password" setting on user accounts effective:
<!--more-->

When users are delegated the permissions to do password resets on user accounts with ADS_UF_PASSWD_NOTREQD, they can set a blank password.
<!--more-->
 
A normal change password procedure by a user do not follow the **ADS_UF_PASSWD_NOTREQD**, it will follow the password policy in your domain or fine grained password policy if you got defined for the user. 
<!--more-->

So let say that an user with the delegate right to do password reset accidentally press OK in the password reset dialog box without the "User must change password at next logon" or someone in your organization with permissions to create user objects accentually runs a script that sets blank password.  Then you will have accounts in you domain with no password.
 <!--more-->

## How do I find accounts with ADS_UF_PASSWD_NOTREQD?
<!--more-->
How will I know any of the accounts in my domain have "password not required" set?
The easiest way to do it is to do a search with ADUC (Active Directory Users and Computers) mmc snap-in.
<!--more-->

1. Right click the domain root.
2. Select **Find....**
3. In the Find: drop down box select **Custom Search**.
4. Click the **Advanced** tab.
5. In the **Enter LDAP Query:** field type: **(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32))**.
6. Click **Find Now**.
<!--more-->

## How to create users
<!--more-->

To create users without allowing blank passwords you must deal with the userAccountContol values:
<!--more-->

"When a new user account is created, the [userAccountControl](https://docs.microsoft.com/en-us/windows/desktop/ADSchema/a-useraccountcontrol)  attribute for the account automatically has the **UF_PASSWD_NOTREQD** flag set, which indicates that no password is required for the account. If the security policies of the domain that the account is created in requires a password for all user accounts, then the **UF_PASSWD_NOTREQD** flag must be removed from the userAccountControl attribute for the account."
<!--more-->

Here you can read on how to create user accounts:
<!--more-->
[Creating a user (Windows)](https://docs.microsoft.com/en-us/windows/desktop/AD/creating-a-user)
<!--more-->

PASSWD_NOTREQD flag:
<!--more-->
<font>
|  Binary  | Decimal  | C# Constant | VB Constant | VB Script Constant ||
|------------|------------|------------|------------|------------|------------|
| 00000000000000000000000000100000 | 32 | 0x0020 | H20 | 0x320020 | ADS_UF_PASSWD_NOTREQD |
<!--more-->

This Vbscript code example will create a user with UF_PASSWD_NOTREQD. **The user will be allowed using blank passwords**.
<!--more-->

{{< highlight vb >}}
Set objOU = GetObject("LDAP://ou=sales,dc=contoso,dc=com")
Set objUser = objOU.Create("User", "cn=jsmith")
objUser.Put "sAMAccountName","jsmith"
objUser.Put "givenName","james"
objUser.SetInfo
objUser.put "userPrincipalName",objUser.sAMAccountName & "@contoso.com"
objUser.AccountDisabled = False
strPassword = "P@ssW0rdPh@rse"
objUser.SetPassword strPassword
objUser.SetInfo
{{< / highlight >}}
<!--more-->

This Vbscript code example manage the userAccountControl attribute. It removes both the disabled state and "password not required" setting:
<!--more-->

{{< highlight vb >}}
Set objOU = GetObject("LDAP://ou=sales,dc=contoso,dc=com")
Set objUser = objOU.Create("User", "cn=jsmith")
objUser.Put "sAMAccountName","jsmith"
objUser.Put "givenName","james"
objUser.SetInfo
objUser.put "userPrincipalName",objUser.sAMAccountName & "@contoso.com"
Const ADS_UF_ACCOUNT_DISABLE = 2
Const ADS_UF_PASSWD_NOTREQD = 32
intUAc = objUser.Get ("userAccountControl")
objUser.put  "userAccountControl", intUAc And (Not ADS_UF_PASSWD_NOTREQD) And (Not ADS_UF_ACCOUNT_DISABLE)
strPassword = "P@ssW0rdPh@rse"
objUser.SetPassword strPassword
objUser.SetInfo
{{< / highlight >}}
<!--more-->

## How do I know if I got blank passwords and how do I deal with it?
<!--more-->

Well, you can run a script to test every account against a blank password or why not find users with passwords that don't comply with the password policy and remove the user setting for other users at the same time? :)
<!--more-->

Here's a code-sample that remove the **ADS_UF_PASSWD_NOTREQD**. If a user has a blank password the script will report an error stating it does not follow the password policy for the domain, as long as you have a password policy in the domain that requires minimum length above zero characters.
If the script succeeds it will also report the status of the account, since if the account is also disabled it still could have a blank password.
<!--more-->
You could test your environment with this code-sample and review the output.
<!--more-->

Hopefully you do not have accounts with **ADS_UF_PASSWD_NOTREQD**. If you do you follow this procedure to find them.
<!--more-->

You could still of course have accounts with blank passwords in case you had a domain password policy with no minimum password length. To remediate you have to make sure your password policies are in line with you security policy and that users are required to change their passwords and do not have "Password never expires" ticked in.
<!--more-->

