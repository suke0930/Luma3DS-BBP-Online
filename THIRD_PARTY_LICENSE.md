# 第三者ソフトウェアのライセンス

Luma3DS全体のライセンスは[GPLv3](LICENSE)です。

## 同梱コード

| 部品 | ライセンス | 著作権表示・本文 |
|---|---|---|
| inih | BSD-3-Clause | Copyright (C) 2009-2020, Ben Hoyt。[本文](arm9/source/LICENSE.txt) |
| fmtの元実装 | BSD-3-Clause | [Michael Ringgaardのnotice](licenses/fmt-BSD-3-Clause.txt) |
| Monocypher | BSD-2-Clauseを選択 | [Loup Vaillantのnotice](licenses/monocypher-BSD-2-Clause.txt) |
| Loader、PM、PXI、SM | MIT | [Loader](sysmodules/loader/LICENSE)、[PM](sysmodules/pm/LICENSE)、[PXI](sysmodules/pxi/LICENSE)、[SM](sysmodules/sm/LICENSE) |
| sRGB画面フィルタのテーブル | MIT | [LumaTeamのnotice](licenses/screen-filters-MIT.txt) |
| GDB stub、miniSOC、sdmmc | GPLv3を選択 | 各ソースのヘッダ、[GPL本文](LICENSE) |
| Redshift | GPL-3.0-or-later | [ソースのヘッダ](sysmodules/rosalina/source/redshift/colorramp.c)、[GPL本文](LICENSE) |
| FatFs | FatFsのライセンス | [ソースのヘッダ](arm9/source/fatfs/ff.c) |
| csvc、luma_shared_config | zlib系 | [本文](licenses/luma-zlib.txt) |

## リンクされる依存物

| 部品・版 | ライセンス・本文 | ソース |
|---|---|---|
| libctru 2.7.0 | [zlib](licenses/libctru-zlib.txt) | [v2.7.0](https://github.com/devkitPro/libctru/tree/v2.7.0) |
| devkitarm-newlib 4.6.0.20260123-5 | [COPYING.NEWLIB](licenses/COPYING.NEWLIB)、[COPYING.LIBGLOSS](licenses/COPYING.LIBGLOSS)、[devkitPro追加分](licenses/NEWLIB-DEVKITPRO-NOTICES.txt) | [公式archive](https://sourceware.org/pub/newlib/newlib-4.6.0.20260123.tar.gz)と[devkitPro patch](https://github.com/devkitPro/buildscripts/blob/174e0edc3f320f53025cd9c662493e22dffbd84e/patches/newlib-4.6.0.20260123-5.patch) |
| devkitarm-crtls 1.2.6の3dsx_crt0.s | [MPL-2.0](licenses/MPL-2.0.txt) | [同梱ソース](licenses/devkitarm-crtls-1.2.6/3dsx_crt0.s)、[v1.2.6](https://github.com/devkitPro/devkitarm-crtls/tree/9788af74f0f3cfd903cffdc903d514fc073a0f95) |
| GCC 16.1.0のruntime | [GPLv3](LICENSE)と[GCC Runtime Library Exception 3.1](licenses/GCC-RUNTIME-EXCEPTION-3.1.txt) | [GCC 16.1.0](https://github.com/gcc-mirror/gcc/tree/releases/gcc-16.1.0/libgcc) |
