# I219 network driver: upstream notices

PaOS's Intel I219 network driver (`src/dev/net/e1000e.asm`) is derived from the upstream sources listed below.
As their licenses require, their copyright and license notices are reproduced here unchanged.

## Notice 1

- [freebsd/freebsd-src / sys/dev/e1000/e1000_ich8lan.c](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_ich8lan.c) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `59ea2bcbb79a40e5981d7e3944b422e8461a649e7472249c6197ac2b1e28da10`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_ich8lan.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_ich8lan.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `71e83003927317656be2e65dad8161a3e52810d4c4809058738b722b5df85920`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_phy.c](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_phy.c) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `82acb2b9b26506aad8e032db1f617733fac672b974663dd5ec8fda3db2320a4b`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_phy.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_phy.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `6a8fbfeca2b585a6220a72f82998fb9021ee9586072b0c9161b2fa771f1c8a19`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_mac.c](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_mac.c) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `031553a97faa53ec89b8a137c51ada23356cd82044b6967e36c9367f8fcee208`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_regs.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_regs.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `b5a2b1fda047727bf66e23eaad50e9ac1247a0f232c60b67224786b46933abfa`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_defines.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_defines.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `3cf2baf6107808b46c29ed55c9008f003c1bb68f89625a5c8a6ec2c35bc9476c`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_api.c](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_api.c) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `722b9cf0b1934891ccd15065db671d564cb4e76ee76009937c8921ae39fa3378`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_hw.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_hw.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `7431e8bc527f6a35306e171d92473754dbfb5e779cb2aa51625eee745f576ae5`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_82575.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_82575.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `3dc4243a68028db6e170c27fbf3386c93a4c7deefdd79f2efd1e2ad131dfaefd`.
- [freebsd/freebsd-src / sys/dev/e1000/e1000_82571.c](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/e1000_82571.c) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `e146d707f40b6362c7ab921db67b9b4f3438d21f9979d44b9f9526930a119fe6`.

```text
/******************************************************************************
  SPDX-License-Identifier: BSD-3-Clause

  Copyright (c) 2001-2020, Intel Corporation
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

   3. Neither the name of the Intel Corporation nor the names of its
      contributors may be used to endorse or promote products derived from
      this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE.

******************************************************************************/
```

## Notice 2

- [freebsd/freebsd-src / sys/dev/e1000/if_em.c](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/if_em.c) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `83d07d0a770ff4e89325ec74ff182ee0753d66a0d743863661dedf8f12a3f452`.
- [freebsd/freebsd-src / sys/dev/e1000/if_em.h](https://raw.githubusercontent.com/freebsd/freebsd-src/65b872380ed7f7900fc581d482c5586eeca9e184/sys/dev/e1000/if_em.h) — commit `65b872380ed7f7900fc581d482c5586eeca9e184`, SHA-256 `179eb160e69b1888396f0939ab78db7215dd0a695d8ca1b8855e7c104d6faac6`.

```text
/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2001-2024, Intel Corporation
 * Copyright (c) 2016 Nicole Graziano <nicole@nextbsd.org>
 * Copyright (c) 2024 Kevin Bowling <kbowling@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
```

## Notice 3

- [DPDK/dpdk / drivers/net/intel/e1000/em_rxtx.c](https://raw.githubusercontent.com/DPDK/dpdk/49bb9a5f7ae51128de7132ffe265192413643bcb/drivers/net/intel/e1000/em_rxtx.c) — commit `49bb9a5f7ae51128de7132ffe265192413643bcb`, SHA-256 `878f64bebef3757d3241469dd7b3dc07d7dc0fe7802c3753b1d90217e88c8b98`.
- [DPDK/dpdk / drivers/net/intel/e1000/em_ethdev.c](https://raw.githubusercontent.com/DPDK/dpdk/49bb9a5f7ae51128de7132ffe265192413643bcb/drivers/net/intel/e1000/em_ethdev.c) — commit `49bb9a5f7ae51128de7132ffe265192413643bcb`, SHA-256 `ebbac8f1a5a45415cf5d3300029f8bff82fe27619935f573e25746675bda8d31`.

```text
/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 */
```

## DPDK BSD-3-Clause terms

The DPDK copyright headers above use these [pinned repository terms](https://raw.githubusercontent.com/DPDK/dpdk/49bb9a5f7ae51128de7132ffe265192413643bcb/license/bsd-3-clause.txt).

```text
Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
```
