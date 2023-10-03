# GodotSteam Server for GDExtension
An open-source and fully functional Steamworks SDK / API server module and plug-in for the Godot Game Engine (version 4.x). For the Windows 32/64-bit, Linux 32/64-bit, and Mac uinversal platforms. 

Additional flavors include:
- [Godot 2.x](https://github.com/CoaguCo-Industries/GodotSteam/tree/godot2)
- [Godot 3.x](https://github.com/CoaguCo-Industries/GodotSteam/tree/godot3)
- [Godot 4.x](https://github.com/CoaguCo-Industries/GodotSteam/tree/godot4)
- [GDNative](https://github.com/CoaguCo-Industries/GodotSteam/tree/gdnative)
- [Server 3.x](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/server3)
- [Server 4.x](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/server4)
- [Server GDExtension](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/gdextension)
- [Server GDNative](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/gdnative)

Documentation
---
[Documentation is available here](https://godotsteam.com/).

Feel free to chat with us about Godotteam on the [CoaguCo Discord server](https://discord.gg/SJRSq6K).

Current Build
---
You can [download pre-compiled versions _(currently v4.0)_ of this repo here](https://github.com/CoaguCo-Industries/GodotSteam-Server/releases).

**Version 4.0 Changes**
- Added: missing server functions from steam_gameserver.h
- Added: missing enums for server modes
- Added: in-editor documentation
- Changed: various improvements under-the-hood
- Changed: reorganized some constants
- Removed: unused enums, signals, functions
- Removed: unnecessary classes that are not part of the server build

[You can read more change-logs here](https://godotsteam.com/changelog/server_gdextension/).

Known Issues
---
- GDExtension for 4.1 is **not** compatible with 4.0.3 or lower. Please check the versions you are using.
- Steam overlay will not work when running your game from the editor if you are using Forward+ as the renderer.  It does work with Compatibility though.  Your exported project will work perfectly fine in the Steam client, however.
- **Using MinGW causes crashes.** I strongly recommend you **do not use MinGW** to compile at this time.

Quick How-To
---
Obtain the plugin through one of two ways:
- Visit the [Godot Asset Library](https://godotengine.org/asset-library/asset/2218) either through the website or in the editor and search for GodotSteam Server.
- Download this repo and unzip it into the base of your game project.

You will need to add the steam_appid.txt file with 480 or your game's app ID to where ever you have your Godot editor.  It should just work without having to do anything else.

Tinker with Steamworks!

Usage
----------
Do not use the GDExtension version of GodotSteam Server with any of the module versions whether it be our pre-compiled versions or ones you compile.  They are not compatible with each other.

When exporting with the GDExtension version, please use the normal Godot Engine templates instead of our GodotSteam Server templates or you will have a lot of issues.

Donate
---
Pull-requests are the best way to help the project out but you can also donate through [Github Sponsors](https://github.com/sponsors/Gramps), [Ko-Fi](https://ko-fi.com/grampsgarcia), or [Paypal](https://www.paypal.me/sithlordkyle)!

License
---
MIT license
