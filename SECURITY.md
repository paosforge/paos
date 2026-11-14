# Security policy (source preview)

This repository is a source preview. There are no releases, images or downloads yet, so nothing here runs on your machine unless you build it yourself.

## Please report security problems privately

**Do not post details of a security problem anywhere public.**

Email **security@paosforge.com**. Say that you have a security report, and **don't include the details in your first message**. We will reply privately and agree how you send them.

When we ask for details, these help:
- the snapshot (source version in the README) and the file and line, or the component;
- how an attacker reaches it (network, USB, file, app, guest, boot);
- a reproducer: a QEMU command, an input file, or steps;
- whether an AI tool helped, and which one. This is for our records, not a penalty.

## What we promise

- A reply from a person. We aim for 3 business days.
- Coordinated disclosure: 90 days by default from your report, or sooner when a fix ships. We agree changes with you.
- Credit, by name or handle as you choose. If an AI tool found the problem, the person who sent the report gets the credit.
- No cash rewards. Credit only.

This is a one-person project. Software agents may help sort reports and try to reproduce them in an isolated test machine; a person confirms every valid report and sends the reply.

## Safe harbor

If you research PaOS in good faith under this policy, we will not take legal action against you and will not ask anyone else to. Good faith means:
- you test on your own machines and your own data, or with clear permission;
- you don't access, change or keep other people's data;
- you don't harm others' service or systems;
- you give us a reasonable time to fix before you publish.

If in doubt, ask us first.

## Scope

In scope: the PaOS source in this repository (core, boot chain, Rescue, SDK).
Out of scope: bugs in upstream projects that we haven't changed (please report those upstream, and tell us if PaOS is affected); paosforge.com's hosting provider; social engineering; denial of service by flooding; attacks that need a firmware or hardware implant.
