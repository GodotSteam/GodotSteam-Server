# GodotSteam Server for Godot Engine 3.x | Community Edition
An open-source and fully functional Steamworks SDK / API server module and plug-in for the Godot Game Engine (version 3.x). For the Windows, Linux, and Mac platforms. 

Additional Flavors
---
Pre-Compiles | Plug-ins | Server | Examples/Demos
--- | --- | --- | ---
[Godot 2.x](https://github.com/CoaguCo-Industries/GodotSteam/tree/godot2)| [GDNative](https://github.com/CoaguCo-Industries/GodotSteam/tree/gdnative) | [Server 3.x](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/godot3) | [Godot 3.x](https://github.com/CoaguCo-Industries/GodotSteam-Example-Project/tree/godot3)
[Godot 3.x](https://github.com/CoaguCo-Industries/GodotSteam/tree/godot3) | [GDExtension](https://github.com/CoaguCo-Industries/GodotSteam/tree/gdextension) | [Server 4.x](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/godot4) |  [Godot 4.x](https://github.com/CoaguCo-Industries/GodotSteam-Example-Project/tree/godot4)
[Godot 4.x](https://github.com/CoaguCo-Industries/GodotSteam/tree/godot4) | --- | [GDNative](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/gdnative) | [Server 3.x](https://github.com/CoaguCo-Industries/GodotSteam-Example-Project/tree/server3)
[Multiplayer Peer](https://github.com/CoaguCo-Industries/GodotSteam/tree/multiplayer-peer)| --- | [GDExtension](https://github.com/CoaguCo-Industries/GodotSteam-Server/tree/gdextension) | [Server 4.x](https://github.com/CoaguCo-Industries/GodotSteam-Example-Project/tree/server4)

Documentation
---
[Documentation is available here](https://godotsteam.com/). You can also check out the Search Help section inside Godot Engine after compiling it with GodotSteam Server.

Feel free to chat with us about GodotSteam on the [CoaguCo Discord server](https://discord.gg/SJRSq6K).

Current Build
---
You can [download pre-compiled versions of this repo here](https://github.com/CoaguCo-Industries/GodotSteam-Server/releases).

**Version 3.3 Changes**
- Changed: constants list to add missing and remove unused
- Changed: Networking Messages, Sockets, and Utils now use Steam IDs instead of identity system
- Changed: various bits and pieces
- Changed: IP logic for all related functions
- Changed: UserUGCListSortOrder enums for readability
- Changed: UGCContentDescriptorID enums for readability
- Changed: `getResultStatus()` now returns the integer / enum
- Changed: `getAuthSessionTicket()` now defaults to 0 for Steam ID
- Fixed: wrong string IP conversions, ***thanks to jeremybeier***
- Fixed: typo with UGC_MATCHING_UGC_TYPE_ITEMS enum
- Fixed: minor case issue with Workshop enums
- Fixed: typo with NETWORKING_CONFIG_TYPE_STRING enum
- Removed: unnecessary enums
- Removed: Networking Types identity system and related bits
- Removed: P2P Networking constants as they are duplicates of the P2PSend enum
- Removed: `getIdentity()` as it is redundant now

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

Known Issues
---
- **Using MinGW causes crashes.** I strong recommend you **do not use MinGW** to compile at this time.

"Quick" How-To
---
For complete instructions on how to build the Godot 3.x version of GodotSteam Server from scratch, [please refer to our documentation's 'How-To Servers' section.](https://godotsteam.com/howto/server/) It will have the most up-to-date information.

Alternatively, you can just [download the pre-compiled versions in our Releases section](https://github.com/CoaguCo-Industries/GodotSteam-Server/releases) and skip compiling it yourself!

Donate
---
Pull-requests are the best way to help the project out but you can also donate through [Github Sponsors](https://github.com/sponsors/Gramps)!

License
---
MIT license
