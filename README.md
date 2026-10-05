# Luma3DS

[English](README.md) | [日本語](README_ja.md)

![GitHub Downloads (all assets, all releases)](https://img.shields.io/github/downloads/suke0930/Luma3DS-BBP-Online/total)
![License](https://img.shields.io/badge/License-GPLv3-blue.svg)

*Nintendo 3DS "Custom Firmware"*

> [!NOTE]
> ### Band Brothers P Online (Luma3DS Fork)
>
> This Luma3DS fork lets you play **Daigassou! Band Brothers P**'s local wireless multiplayer over the internet.
>
> It forwards the game's local wireless traffic (`nwm::UDS` / "Play with nearby people") through a relay server.
>
> - **In-game Controls**: After setting up Relay, select local wireless multiplayer in-game. One player creates a room and others join.
> - **Rosalina "BBP Online" Menu**: With BBP closed, press <kbd>L</kbd>+<kbd>Down</kbd>+<kbd>Select</kbd> and open BBP Online to configure settings. See [Playing online](#playing-online) for menu items and controls. Settings cannot be changed while BBP is running.
> - **Server Status**: Open "Status" in the menu to check connection latency (Ping/RTT), online player count, recruiting rooms per channel, and rooms currently in game (<kbd>X</kbd> to refresh, <kbd>B</kbd> to back). This remains available while BBP is running.
> - **Encrypted Relay**: Traffic between each console and the relay server is encrypted using Noise NN (`ChaCha20-Poly1305` / `BLAKE2b`). The relay server decrypts the traffic. The connection does not authenticate the server to verify that it is the intended relay.
> - **Relay Servers**: The default server is `bbprelay.f5.si:24873`. You can configure other relay servers using Custom 1–3 in Rosalina.
> - **Prerequisites**: All players need a 3DS console running custom firmware (boot9strap/Luma3DS) connected to Wi-Fi, and a retail copy of *Daigassou! Band Brothers P* with Update Ver. 2.1 installed. Download Play is not supported.
>
> *日本語の詳しい説明は [README_ja.md](README_ja.md) をご覧ください。*


![Boot menu screenshot](img/boot_menu_v1321.png)
![Rosalina menu screenshot](img/rosalina_menu_v1321.png)

## Description
**Luma3DS** patches and reimplements significant parts of the system software running on all models of the Nintendo 3DS family of consoles. It aims to greatly improve the user experience and support the 3DS far beyond its end-of-life. Features include:

* **First-class support for homebrew applications**
* **Rosalina**, an overlay menu (triggered by <kbd>L+Down+Select</kbd> by default), allowing things like:
    * Taking screenshots while in game
    * Blue light filters and other screen filters
    * Input redirection to play with external devices, such as controllers
    * Using cheat codes
    * Setting time and date accurately from the network (NTP)
    * ... and much more!
* **Many game modding features**, such as, but not limited to:
    * Game plugins (in 3GX format)
    * Per-game language overrides ("locale emulation")
    * Asset content path redirection ("LayeredFS")
* **Support for user-provided patches and/or full "system modules" replacements**, an essential feature for Nintendo Network replacements (amongst other projects)
* A **fully-fledged GDB stub**, allowing homebrew developers and reverse-engineers alike to work much more efficiently
* Ability to chainload other firmware files, including other versions of itself
* ... and much more!

## Playing online

Configure settings in the Rosalina menu before launching the game. Settings cannot be changed while BBP is running (close the game to change settings).

### Opening the menu and controls
1. With BBP closed, press <kbd>L</kbd>+<kbd>Down</kbd>+<kbd>Select</kbd> to open the Rosalina menu.
2. Select **BBP Online**.

#### Menu items
- **Relay: OFF / ON**
  Enables the relay feature. Press <kbd>A</kbd> to toggle. Turn it ON before launching the game.
- **Room passphrase** (4-digit PIN)
  Sets the room access PIN. Press <kbd>A</kbd> to open the editor. Use <kbd>Left</kbd>/<kbd>Right</kbd> to select a digit, <kbd>Up</kbd>/<kbd>Down</kbd> to change the value, and <kbd>A</kbd> to save (<kbd>B</kbd> to cancel).
  - `0000` (default): Public play. Rooms appear to everyone on the selected channel.
  - `0001`–`9999`: Group play (PIN). Rooms only appear to players with the exact same PIN (channel is ignored).
- **Channel** (1–5)
  Separates public recruiting slots (up to 4 rooms per channel). Press <kbd>A</kbd> to open the list, select with <kbd>Up</kbd>/<kbd>Down</kbd>, and save with <kbd>A</kbd>. Has no effect when using a PIN.
- **Status**
  Checks relay connection latency (Ping/RTT), online player count, recruiting rooms per channel, and rooms currently in game (<kbd>X</kbd> to refresh, <kbd>B</kbd> to back). Available while BBP is running.
- **Relay server...**
  Selects the relay server. Default is Official (`bbprelay.f5.si:24873`). For custom servers, select Custom 1–3, press <kbd>X</kbd> to edit IPv4:port, and press <kbd>A</kbd> to select.

### Settings persistence
- **Relay, Channel, Room passphrase**
  Reset to defaults (Relay: OFF, Channel: 1, PIN: 0000) every time the console reboots. Remember to turn Relay ON before launching BBP.
- **Relay server... (custom servers)**
  Custom addresses and your server selection are automatically saved to your SD card and persist across reboots.

### How to play on a public channel
1. Keep the default settings (`Channel: 1`, `Room passphrase: 0000`).
2. Select `Relay` and press <kbd>A</kbd> to turn it **ON**.
3. Press <kbd>B</kbd> to close Rosalina and launch BBP.
4. Select local wireless multiplayer in-game. **One player creates a room, and other players join the room.**
*If all four room slots on Channel 1 are full, close BBP and switch `Channel` to an open channel (2–5). You can check open slots on the Status screen.*

### How to play within your group (PIN)
1. Agree on a 4-digit PIN (`0001`–`9999`) with your friends beforehand.
2. Select `Room passphrase`, enter the PIN, and press <kbd>A</kbd> to save.
3. Select `Relay` and press <kbd>A</kbd> to turn it **ON**.
4. Press <kbd>B</kbd> to close Rosalina and launch BBP.
5. Select local wireless multiplayer in-game. **One player creates a room, and other players join.** Only players with the matching PIN will see the room.
*Anyone using the same PIN can join, so share it only with people in your group.*

## Installation and upgrade
Luma3DS requires [boot9strap](https://github.com/SciresM/boot9strap) to run.

For BBP Online, download `boot.firm` from [this fork's releases](https://github.com/suke0930/Luma3DS-BBP-Online/releases). Back up your existing `boot.firm`, then copy the downloaded file to the root of your SD card. Standard [upstream Luma3DS releases](https://github.com/LumaTeam/Luma3DS/releases/latest) do not include BBP Online.

## Basic usage
**The main Luma3DS configuration menu** can be accessed by pressing <kbd>Select</kbd> at boot. The configuration file is stored in `/luma/config.ini` on the SD card (or `/rw/luma/config.ini` on the CTRNAND partition if Luma3DS has been launched from the CTRNAND partition, which happens when SD card is missing).

**The chainloader menu** is accessed by pressing <kbd>Start</kbd> at boot, or from the configuration menu. Payloads are expected to be located in `/luma/payloads` with the `.firm` extension; if there is only one such payload, the aforementioned selection menu will be skipped. Hotkeys can be assigned to payload, for example `x_test.firm` will be chainloaded when <kbd>X</kbd> is pressed at boot.

**The overlay menu, Rosalina**, has a default button combination: <kbd>L+Down+Select</kbd>. For greater flexibility, most Rosalina menu settings aren't saved automatically, hence the "Save settings" option.

**GDB ports**, when enabled, are `4000-4002` for the normal ports. Use of `attach` in "extended-remote" mode, alongside `info os processes` is supported and encouraged (for reverse-engineering, also check out `monitor getmemregions`). The port for the break-on-start feature is `4003` without "extended-remote". Both devkitARM-patched GDB and IDA Pro (without "stepping support" enabled) are actively supported.

We have a wiki, however it is currently very outdated.

## Components

Luma3DS consists of multiple components. While the code style within each component is mostly consistent, these components have been written over many years and may not reflect how maintainers would write new code in new components/projects:

* **arm9**, **arm11**: baremetal main settings menu, chainloader and firmware loader. Aside from showing settings and chainloading to other homebrew firmware files on demand, it is responsible for patching the official firmware to modify `Process9` code and to inject all other custom components. This was the first component ever written for this project, in 2015
* **k11_extension**: code extending the Arm11 `NATIVE_FIRM` kernel (`Kernel11`). It is injected by the above mentioned baremetal loader into the kernel by hooking its startup code, then hooks itself into the rest of the kernel. Its features include hooking system calls (SVCs), introducing new SVCs and hooking into interprocess communications, to bypass limitations in Nintendo's system design. This is the component that allows Rosalina to pause other processes on overlay menu entry, for example. This was written at a time when we didn't fully reverse-engineer the kernel, and originally released in 2017 alongside Rosalina. Further hooks for "game plugin" support have been merged in 2023
* **sysmodules**: reimplementation of "system modules" (processes) of the 3DS's OS (except for Rosalina being custom), currently only initial processes loaded directly in-memory by the kernel ("kernel initial process", or KIP in short)
    * **loader**: process that loads non-KIP processes from storage. Because this is the perfect place to patch/replace executable code, this is where all process patches are done, enabling in particular "game modding" features. This is also the sysmodule handling 3DSX homebrew loading. Introduced in 2016
    * _**rosalina**_: the most important component of Luma3DS and custom KIP: overlay menu, GDB server, `err:f` (fatal error screen) reimplementation, and much more. Introduced in mid-2017, and has continuously undergone changes and received many external contributions ever since
    * **pxi**: Arm11<>Arm9 communication KIP, reimplemented just for the sake of it. Introduced late 2017
    * **sm**: service manager KIP, reimplemented to remove service access control restrictions. Introduced late 2017
    * **pm**: process manager KIP responsible of starting/terminating processes and instructing `loader` to load them. The reimplementation allows for break-on-start GDB feature in Rosalina, as well as lifting FS access control restrictions the proper way. Introduced in 2019

## Maintainers

* **[@TuxSH](https://github.com/TuxSH)**: lead developer, created and maintains most features of the project. Joined in 2016
* **[@AuroraWright](https://github.com/AuroraWright)**: author of the project, implemented the core features (most of the baremetal boot settings menu and firmware loading code) with successful design decisions that made the project popular. Created the project in 2015, currently inactive
* **[@PabloMK7](https://github.com/PabloMK7)**: maintainer of the plugin loader feature merged for the v13.0 release. Joined in 2023

## Roadmap

There are still a lot more features and consolidation planned for Luma3DS! Here is a list of what is currently in store:

* Full reimplementation of `TwlBg` and `AgbBg`. This will allow much better, and more configurable, upscaling for top screen in DS and GBA games (except on Old 2DS). This is currently being developed privately in C++23 (no ETA). While this is quite a difficult endeavor as this requires rewriting the entire driver stack in semi-bare-metal (limited kernel with no IPC), this is the most critical feature for Luma3DS to have and will make driver sysmodule reimplementation trivial
* Reimplementation of `Process9` for `TWL_FIRM` and `AGB_FIRM` to allow for more features in DS and GBA compatibility mode (ones that require file access)
* Eventually, a full `Kernel11` reimplementation

## Known issues

* **Cheat engine crashes with some applications, in particular Pokémon games**: there is a race condition in Nintendo's `Kernel11` pertaining to attaching a new `KDebugThread` to a `KThread` on thread creation, and another thread null-dereferencing `thread->debugThread`. This causes the cheat engine to crashes games that create and destroy many threads all the time (like Pokémon).
    * For these games, having a **dedicated "game plugin"** is the only alternative until `Kernel11` is reimplemented.
* **Applications reacting to Rosalina menu button combo**: Rosalina merely polls button input at an interval to know when to show the menu. This means that the Rosalina menu combo can sometimes be processed by the game/process that is going to be paused.
    * You can **change the menu combo** in the "Miscellaneous options" submenu (then save it with "Save settings" in the main menu) to work around this.

## Building from source

To build Luma3DS, the following is needed:
* git
* [makerom](https://github.com/jakcron/Project_CTR) in `$PATH`
* [firmtool](https://github.com/TuxSH/firmtool) installed
* up-to-date devkitARM and libctru:
    * install `dkp-pacman` (or, for distributions that already provide pacman, add repositories): https://devkitpro.org/wiki/devkitPro_pacman
    * install packages from `3ds-dev` metapackage: `sudo dkp-pacman -S 3ds-dev --needed`
    * while libctru and Luma3DS releases are kept in sync, you may have to build libctru from source for non-release Luma3DS commits

While Luma3DS releases are bundled with `3ds-hbmenu`, Luma3DS actually compiles into one single file: `boot.firm`. Just copy it over to the root of your SD card ([ftpd](https://github.com/mtheall/ftpd) is the easiest way to do so), and you're done.

## Licensing
This software is licensed under the terms of the GPLv3. You can find a copy of the license in the LICENSE.txt file.

Files in the GDB stub are instead triple-licensed as MIT or "GPLv2 or any later version", in which case it's specified in the file header. PM, SM, PXI reimplementations are also licensed under MIT.

## Credits

Luma3DS would not be what it is without the contributions and constructive feedback of many. We would like to thanks in particular:

* **[@devkitPro](https://github.com/devkitPro)** (especially **[@fincs](https://github.com/fincs)**, **[@WinterMute](https://github.com/WinterMute)** and **[@mtheall](https://github.com/mtheall)**) for providing quality and easy-to-use toolchains with bleeding-edge GCC, and for their continued technical advice
* **[@Nanquitas](https://github.com/Nanquitas)** for the initial version of the game plugin loader code as well as very useful contributions to the GDB stub
* **[@piepie62](https://github.com/piepie62)** for the current implementation of the Rosalina cheat engine, **Duckbill** for its original implementation
* **[@panicbit](https://github.com/panicbit)** for the original implementation of screen filters in Rosalina
* **[@jasondellaluce](https://github.com/jasondellaluce)** for LayeredFS
* **[@LiquidFenrir](https://github.com/LiquidFenrir)** for the memory viewer inside Rosalina's "Process List"
* **ChaN** for [FatFs](http://elm-chan.org/fsw/ff/00index_e.html)
* Everyone who has contributed to the Luma3DS repository
* Everyone who has assisted with troubleshooting end-users
* Everyone who has provided constructive feedback to Luma3DS

## Copyright

- This software lets people who purchased and own the game continue playing together after the official online services ended.
- This project is an unofficial, fan-made open-source project and is not affiliated with Nintendo Co., Ltd.
- This repository does not contain or distribute Nintendo's copyrighted materials, such as game ROMs, update data, assets or official binaries.

## Special Thanks
AI tools including GPT and DeepSeek were used in the development of this fork.

- **[Nintendo](https://www.nintendo.com/)**: Nintendo and the developers of *Daigassou! Band Brothers P*.
- **[Luma3DS](https://github.com/LumaTeam/Luma3DS)**: The Luma3DS developers and contributors for the custom firmware base.
- **[DDNS Now (f5.si)](https://ddns.kuku.lu/)**: For providing the free dynamic DNS domain used in the default preset.
