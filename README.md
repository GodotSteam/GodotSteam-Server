# GodotSteam Server for Godot 3.x | Community Edition
An open-source and fully functional Steamworks SDK / API server module and plug-in for the Godot Game Engine (version 3.x). For the Windows, Linux, and Mac platforms. 

Additional Flavors
---
Pre-Compiles | Plug-ins | Server | Examples
--- | --- | --- | ---
[Godot 2.x](https://github.com/GodotSteam/GodotSteam/tree/godot2) | [GDNative](https://github.com/GodotSteam/GodotSteam/tree/gdnative) | [Server 3.x](https://github.com/GodotSteam/GodotSteam-Server/tree/godot3) | [Skillet](https://github.com/GodotSteam/Skillet)
[Godot 3.x](https://github.com/GodotSteam/GodotSteam/tree/godot3) | [GDExtension](https://github.com/GodotSteam/GodotSteam/tree/gdextension) | [Server 4.x](https://github.com/GodotSteam/GodotSteam-Server/tree/godot4) | ---
[Godot 4.x](https://github.com/GodotSteam/GodotSteam/tree/godot4) | --- | [GDNative](https://github.com/GodotSteam/GodotSteam-Server/tree/gdnative) | ---
[MultiplayerPeer](https://github.com/GodotSteam/MultiplayerPeer)| --- | [GDExtension](https://github.com/GodotSteam/GodotSteam-Server/tree/gdextension) | ---

Documentation
---
[Documentation is available here](https://godotsteam.com/). You can also check out the Search Help section inside Godot Engine after compiling it with GodotSteam Server.

Feel free to chat with us about GodotSteam or ask for assistance on the [Discord server](https://discord.gg/SJRSq6K).

Donate
---
Pull-requests are the best way to help the project out but you can also donate through [Github Sponsors](https://github.com/sponsors/Gramps)!

Current Build
---
You can [download pre-compiled versions of this repo here](https://github.com/GodotSteam/GodotSteam-Server/releases).

**Version 3.4 Changes**
- Added: public properties with set/get functions
- Added: failures now print to editor
- Changed: updated to Steamworks SDK 1.61
- Changed: added new enums from newest SDK, removed the now missing ones
- Changed: deprecating `serverInit` in next patch, migrate to `serverInitEx`
- Changed: return typed for `getHTTPResponseHeaderValue` and `getHTTPStreamingResponseBodyData`
- Changed: `configureConnectionLanes` now has correct type for lanes argument
- Changed: NetworkingSockets now take dictionary for options, based on godot4 branch in main GodotSteam repo
- Changed: reworked `getUserAchievement`, `getUserStatFloat`, `getUserStatInt` to mirror godot4 branch in main GodotSteam repo
- Fixed: `setHTTPRequestRawPostBody`, backport from godot4 branch in main GodotSteam repo
- Fixed: `serializeResult` now returns PackedByteArray
- Fixed: misspelled enum

[You can read more change-logs here](https://godotsteam.com/changelog/server3/).

Compatibility
---
While rare, sometimes Steamworks SDK updates will break compatilibity with older GodotSteam versions. Any compatability breaks are noted below. API files (dll, so, dylib) _should_ still work for older version.

Steamworks SDK Version | GodotSteam Version
---|---
1.59 or newer | 3.2 or newer
1.58a or older | 3.1 or older

Versions of GodotSteam that have compatibility breaks introduced.

GodotSteam Version | Broken Compatibility
---|---
3.3| Networking identity system removed, replaced with Steam IDs
4.4 | sendMessages returns an Array

Known Issues
---
- When self-compiling, **do not** use MinGW as it will cause crashes.

Quick How-To
---
For complete instructions on how to build the Godot 3.x version of GodotSteam Server from scratch, [please refer to our documentation's 'How-To Servers' section.](https://godotsteam.com/howto/server/) It will have the most up-to-date information.

Alternatively, you can just [download the pre-compiled versions in our Releases section](https://github.com/GodotSteam/GodotSteam-Server/releases) and skip compiling it yourself!

License
---
MIT license
