# Contributing to the PaOS source preview

Thank you for looking. This repository is a read-only snapshot of PaOS before its first release. You can still help in many ways. Some are welcome now, some are welcome but slow, and some have to wait.

**Pace:** Peter reads everything; replies come weekly.
**Contact:** hello@paosforge.com
Issues and pull requests are turned off for this preview.

## Why some things have to wait

- **The repository is a one-way snapshot.** It is copied out of our private development system, so a pull request here can't be merged directly.
- **Every line of code needs a provenance check** and DCO sign-off before it can go into PaOS. We aren't set up to do that for outside code yet.
- **There is one maintainer.** We'd rather say "not yet" than leave you waiting.

## 1. Welcome now

None of these need a merge or a quick reply.

- **Bug and code-reading reports.** Found something that looks wrong while reading the code? Email hello@paosforge.com with the file, the line, and what you think is wrong. Please name the snapshot (the source version in the README, for example 0.0.300).
- **Security problems: report privately.** Don't post details anywhere public. Email security@paosforge.com with no details in your first message, and we'll reply privately. See [SECURITY.md](SECURITY.md).
- **"My hardware" reports.** Tell us what you'd want to run PaOS on: PC model, network chip, storage, and graphics. This helps us choose what to test next. It is not a request to support your machine, and nothing here installs on it. Please leave out serial numbers and network (MAC) addresses. A read-only hardware check tool for Windows and Linux is planned.
- **Use your own AI to help.** Point Claude, Codex or another assistant at the source. Ask it to review for bugs or security problems, or to explain a part of the code, and send us what it finds. Please check what it found before you send it. We'd rather your AI help find problems than send code patches; we can't merge outside code yet (see above). Later, once the public build recipe is published, we'll add a ready-made prompt that has your AI build PaOS from source and boot it in a virtual machine.
- **Ideas and feature requests.** Please describe the problem it solves for a person, not just the feature.
- **Simulator feedback.** The browser design simulator (https://paosforge.com/simulator/) shows planned behavior. Tell us what feels promising, confusing, or missing.
- **Reviews and write-ups** on your own blog, channel or forum. Honest is better than kind.
- **Apps and tools on the SDK.** The SDK in `sdk/` is Apache-2.0. Build in your own repository under the license you choose. Send us the link and we may list it.

## 2. Welcome, but slow

- **Documentation and typo fixes.** Send a patch (`git diff` or `git format-patch`) or just describe the fix by email. We apply them in batches, with credit in a later snapshot. Please add a `Signed-off-by:` line with your real name (see the [Developer Certificate of Origin](https://developercertificate.org/)) so we can use it.

## 3. Not yet

- Code changes to the PaOS core
- Drivers
- Translations
- Paid bounties

These will open after the 0.1 Preview, when the public repository accepts contributions with DCO sign-off. No CLA.

## Support the build

Support options are coming.

## Privacy

Mail to hello@paosforge.com is read by Peter and may be sorted by an AI assistant. Addresses are never shared. The 0.1 announcement list gets one message.

## Be kind

See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
