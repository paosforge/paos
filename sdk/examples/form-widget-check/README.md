<!-- SPDX-License-Identifier: Apache-2.0 -->
# Form and widget recipe source

This unsigned example ships native form discovery and bounded widget recipes.
It has no signature or enrollment, and has not been run on a candidate.
Use the SDK `diagnose-selectors` command with `manifest.txt` and `recipes.txt`
to check documented selectors and declared recipe permissions offline.
Use `dev-sign` as described in the SDK README to create a development bundle;
the installation owner must separately enroll its public key and authorize APP.

`discover` requests the first descriptor page, the native forms listing and
schemas, the first 384 bytes of the built-in `lock_screen` form metadata, and
the first widget page. Native form inventory varies with the profile; the
forms listing is the native FORMLIST view, not an installed bundle asset loader.
Follow the returned native cursors/pages explicitly to inspect further data.
Separate reads are fresh observations, not an atomic snapshot. APP RUN reports
step code/value and completion, not the nested command's body; read bodies with
the same direct HOOK calls. APP INSPECT shows the literal signed recipe.

`widget_sample` uses literal instance 0 as an editable example, not a durable
widget identity. Discover the intended live instance with `HOOK LIST widget`,
then replace the ID before signing. Missing instances, unsupported fields and
native refusals keep their native semantics. Secret values remain redacted.

For an explicitly chosen scalar widget, a separate recipe can contain
`step HOOK SET widget:12 value 17`, with `gui.write` declared. Replace 12 with
the intended live ID. This selects the existing native WIDGETSET value path;
slider/numeric values use the same clamping and step alignment as GUI input,
and toggle values use the native boolean conversion. The operation preserves
native intent events, ownership/session checks and result code/value. The
permission grants no ticket or owner authority. A remote APP's outer ticket
is still consumed before any protected nested step and cannot authorize it.
Text/input/action injection and widget creation are outside this recipe set.
