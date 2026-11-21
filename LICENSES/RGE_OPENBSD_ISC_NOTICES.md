# OpenBSD rge(4) notices for the RTL8125 and RTL8126 drivers

Retained for `src/dev/net/rtl8125.asm`, `src/dev/net/rtl8126.asm` and
`src/dev/net/rtl8126_bsd_facts.inc`. Their headers cite the pinned OpenBSD
`if_rge.c` and `if_rgereg.h` below as protocol references, and
`rtl8126_bsd_facts.inc` carries register and firmware data taken from them.
The ISC terms ask that the copyright notice and permission notice appear in all
copies; built images do not carry source headers, so both notices are
reproduced here verbatim. This is
the standard notice the ISC licence asks for. It records notice compliance
only: driver provenance and similarity review stay open and these notices
confer no runtime acceptance. Exact source bindings are recorded in
`release/SOURCE_COMPONENT_SELECTION.json`.

## Notice 1

- [openbsd/src / sys/dev/pci/if_rge.c](https://raw.githubusercontent.com/openbsd/src/3f3b42af786bd14e88f1249ea29e11025829e930/sys/dev/pci/if_rge.c) — commit `3f3b42af786bd14e88f1249ea29e11025829e930`, SHA-256 `6708163f6dc00657302f8a99e2998a5b656c29df531c61f0a5d2b0fe6b7a7156`.

```text
/*
 * Copyright (c) 2019, 2020, 2023-2025
 *	Kevin Lo <kevlo@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
```

## Notice 2

- [openbsd/src / sys/dev/pci/if_rgereg.h](https://raw.githubusercontent.com/openbsd/src/e574c2d36cbcacf2556088879be336775e80154b/sys/dev/pci/if_rgereg.h) — commit `e574c2d36cbcacf2556088879be336775e80154b`, SHA-256 `8822accf2cda0a392c62a7dbafabe36c314331dc4af20561de92d3ba2355f7e5`.

```text
/*
 * Copyright (c) 2019, 2020, 2025 Kevin Lo <kevlo@openbsd.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
```
