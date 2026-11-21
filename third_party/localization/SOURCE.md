# Public existing UI/help localization source

Six DATA files are byte-for-byte copies of the maintained localization declarations,
originally under `gauntlet_v2/docs/localization/`. The four UI/site/glossary files
retain integration 130ebb9e45a3f1211d1e22344d595fa5e3c7b32f. The two offline Help
files include the reviewed Recovery guidance integrated by 7b3a4f2ac, present at
20dbf7d5a8c0694b40a47ce62a1dc2a2b946e20f. Records 6040–6044 use the existing
English fallback; their five-locale translations remain pending. PaOS-authored
DATA retains MPL-2.0 terms. No native include, translation, stable ID, glossary,
IME, locale policy or glyph is changed by this public-source synchronization.

Run `python3 tools/l10n/gen_ui.py --check` or
`python3 tools/l10n/gen_ui.py --emit NEW_DIRECTORY` from any working directory.
Python 3's standard library suffices. The recipe reads only selected public
files and explicitly pinned Unicode 15.0.0 DATA; no interpreter Unicode tables,
fonts, private factory tools or network are used. Every input, helper, recipe
and original license is admitted before any helper execution or output creation.
The output is the existing l10n_catalog.inc and l10n_glyphs.inc byte for byte,
plus all six existing PCAT1 catalogs and coverage.json from the same compiler.
The original generated comments, source hashes, glossary pin strings and
reviewed-site identity retain their historical strings to preserve exact native
bytes. These strings never direct filesystem reads into gauntlet_v2.

`tools/l10n/{catalog,site_map,emitter}.py` selects the existing deterministic
compiler, reviewed site grammar and emitter functions from rcq38_catalog.py,
rcq38_image_map.py and l10n_bind_check.py at the pinned integration. Their
MPL-2.0 authored algorithms and stable IDs remain unchanged; the emitter adds
strict scalar/duplicate/exact-subset checks. Images, census/adjudication CLI,
factory workflows and their import dependencies are not exported. This public
recipe verifies regeneration only. The established full localization/IME,
placement, content, source binding, width, token and wire checks remain owned
by the existing private audit and runtime reviewers.

The 520 exact original Unifont 15.1.01 16x16 cells, elected OFL-1.1, are in
`third_party/fonts/unifont/unifont-ui-subset.hex`. See its SOURCE.md for pinned
package/input/subset hashes and the original Unifont.COPYING / OFL-1.1.txt.
SOURCES.json binds every selected input/helper/license by exact hash; the public
entry binds that manifest and this recipe. Only bounded unifont-ui source
regeneration is closed, not other nested components or a whole source export.

## Current Explorer and SSH bindings (2026-10-16)

The UI catalog and source-site declaration now match maintained source at
integration d5ad75e6796dff291c9856932ac876e3248ccf1d. IDs 718 and 1264
keep their stable identities and critical flags. All six locale texts describe
the current incomplete/invalid-name refusal and SSH hostname/exec syntax.
These corrections are machine-authored; native-language evaluation is not claimed.
The other UI messages, Help declarations, glyph pixels and compiler are unchanged.
The catalog include is regenerated from these exact declarations; source and
output hashes are refreshed explicitly. Serial/UDP power reasons remain English,
and the maintained private audit still checks literal meaning, VT CRLF framing,
widths, closed power consumers and the RAX-preserving M1 history helper.

## Help and Terminal help glyph closure (2026-10-16)

`catalog.l5.v1.json` (Terminal help lines) is a seventh byte-for-byte DATA copy
from `gauntlet_v2/docs/localization/`. The emitter's glyph closure now spans the
UI, offline Help and L5 catalogs, the three catalog sets the image paints, so
the subset holds 739 original Unifont cells: the 520 above plus 219 Help/L5
ideographs cut verbatim from the same pinned input. Messages, IDs, translations,
PCAT1 catalogs and the catalog include are unchanged; only l10n_glyphs.inc and
its excerpt grow, and SOURCES.json and the gen_ui pins are refreshed explicitly.

## Level-1 ideograph closure (2026-10-16, step B)

`Unihan_IRGSources.level1.txt` is an excerpt of Unicode 15.1.0
`Unihan_IRGSources.txt` (the 11 header lines, then every `kIRG_JSource` J0 row
16-47 and `kIRG_GSource` G0 row 16-55 line, verbatim, in file order;
Unicode-3.0). The emitter adds its 5009 ideographs to the glyph closure, so the
subset holds 5195 original Unifont cells. `level1()` refuses an excerpt with any
other line, a duplicate, another header or a count other than 2965 / 3755.
Messages, IDs, translations, PCAT1 catalogs and the catalog include are
unchanged; only l10n_glyphs.inc and its excerpt grow. SOURCES.json pins the new
file and the gen_ui pins are refreshed explicitly.

## Embedded locale catalogs (2026-10-16, RCQ-38 catalogs)

The emitter now also writes the five other locales' UI and offline-help PCAT1
(es, fr, de, ja, zh-Hans: `catalog.py` LOCALES order == lang_prefs ordinals)
into `l10n_catalog.inc`, inside the trusted range after the English pair, with
per-locale schema + artifact SHA-256 expectations and a numeric offset table
outside it. Messages, IDs, translations and the glyph subset are unchanged;
SOURCES.json pins the new emitter and the gen_ui pins are refreshed explicitly.

## Native lock-card locale closure (2026-10-18)

The UI catalog and reviewed source-site map are byte-for-byte copies of the
maintained declarations accepted in integration
fa22aec9f79fe864637d50299471e57e87b7b26d
(RC-lock-screen-six-locale-card-20261018). They include the ten stable lock-card
IDs 4063–4072 among the 85 active source sites, for en, es, fr, de, ja and
zh-Hans. These translations are machine-authored; native-language evaluation
is not claimed. The public catalog was already synchronized by that integration,
but its manifest pin and the public source-site map were left at the previous
revision, so the public integrity check correctly failed. The original failure
is retained in the correctness handoff; no admission or integrity check is relaxed.

This repair synchronizes the public source-site map, refreshes both input pins
in SOURCES.json, and refreshes the manifest, recipe and catalog-output pins in
gen_ui.py. The catalog input is SHA-256
`dee4fa57179101f15641885f08e538caaabc10fc987b1026c5b07d5c7caf9067`;
the source-site input is SHA-256
`2966545a56da34f5300a6f9b8a7d747639c3dd69e05e08d0a8599bdb1d1d02ba`.
The public compiler reproduces the already accepted native catalog include
(SHA-256 `e6a9b297b218ed7a67afcf3a67e74658f0a80cff1724cef604589c465b093db4`)
and the unchanged 5195-cell glyph include byte for byte. No compiler algorithm,
helper, glyph, native source, authentication behavior or locale text changes.

## History audit provenance closure (2026-10-18)

The accepted History integration a42f6dc844d8b6970dea8f3cdf48daff74b39d96
refreshed the maintained audit source-site identity and catalog schema binding,
and regenerated the native catalog include. The public copies still carried
the preceding source-site and schema digests. The public check correctly
refused that mismatch; the original base failure is retained in the SOURCE
handoff for RC-history-public-locale-closure-20261018.

The public UI catalog and source-site map now exactly copy those maintained
declarations as present in integration 5c3407534467f0b8e6001dd9797e151cd1819bb5.
All 85 active messages, stable IDs, six-locale texts and critical flags are
unchanged. Only the catalog's sites_sha256 and the reviewed audit-source
provenance differ from the previous public declarations. SOURCES.json and
gen_ui.py refresh their exact input, manifest, recipe and output pins. The
public recipe reproduces the already accepted native catalog include and
unchanged glyph include byte for byte. No helper, integrity check, native
source, glyph pixel or authentication behavior changes. Subsequent maintained
localization updates must synchronize these public declarations and regenerate
their closure together.

## Accepted fallback-notice locale records (2026-10-18)

Seven stable keys `boot.notice.*`, IDs 4600–4606, now bind the exact English
fallbacks in `src/svc/command_recovery_state.asm` accepted as 48252ad2 and
integrated as 05a450e0. The UI catalog and site map are synchronized with the
maintained declarations. All seven have explicit en, es, fr, de, ja and zh-Hans
text; the 35 non-English translations are machine-authored and have not had
native-language evaluation. Safe and Rescue remain the product mode names.
The messages report only the accepted interrupted, safe-retry, verified-fallback,
check-failure or Rescue reason; they do not diagnose an attack or promise repair.

The source map advances its revision and current-file hash while retaining the
file's historical inventory hash. The seven new anchors belong to the current
accepted source, not to the historical inventory snapshot. All existing message
IDs, texts, critical flags and translations are retained. As with the other
current RC1 additions, the unshipped catalog stays at initial revision 1; its
complete schema and site digests change and the compiled schema expectations
are regenerated. No catalog admission, helper or digest check is changed.

The existing public recipe regenerates all six PCAT1 artifacts and their embedded
bytes, expectations and numeric IDs; the input, recipe and output pins are
refreshed explicitly. The original 5195 glyph cells remain unchanged. These
records are available for a future native notice renderer. Their maintained
width contracts say unused because no painter consumes them yet; actual
placement, wrapping and six-locale visual verification remain open. The existing
English typed recovery wire, boot selection, authentication and retry behavior
are unchanged.

The synchronization also retains the accepted current History source hashes
already present in the maintained site map (command_audit.asm).
They had not reached the public copy, leaving public regeneration behind the
embedded catalog at the source base. This change carries those accepted map
records forward and synchronizes the public copy; it does not revert them to
the historical source hashes. The inherited public mismatch and the initial
pre-final-pin failures are preserved in the handoff.

## Explorer/SSH source-pin coherence (2026-10-31)

The two maintained source anchors, `src/gui/form_loader.asm` and
`src/gui/terminal_app.asm`, now bind integration
3952daff2ae2684d477271c118b37cf61d2d17f5. Source-map revision 7 refreshes
their 383 row hashes and records drift in ineligible historical anchors; no
accepted ID, literal, classification, eligibility or six-locale text changes.
Other file pins remain historical. The adjudication report is projected from
this exact accepted map, including the seven fallback-notice records omitted
by its previous revision-5 projection.

The maintained/public catalog and site map are synchronized together. The
public input/manifest/recipe and generated catalog pins are refreshed as one
closure. PCAT1 schema identities and expectations change with source provenance;
message payloads, glyphs and helper algorithms stay unchanged. This is source
coherence only, with no native-language, image-binding or runtime credit.

## Current integration correction (2026-10-31)

ADMIN return 89149 is corrected against integration d6f0123d68dbfbe944d1b257aafc197fb1272483.
The Explorer source hash and its 210 matching row hashes now bind that source.
The SSH source still matches its previous pin. Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 8 supersedes revision 7.

## Current integration correction (2026-10-31)

ADMIN return 90089 is corrected against integration 0cdcc9de7e30425fbf97c7c41257e140f43b82e0.
The Explorer source hash and its 210 matching row hashes now bind that source.
The SSH source still matches its previous pin. Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 9 supersedes its preceding revision.

## Current integration correction (2026-10-31)

Settings Apps (SRC return 90299), source pins; source 57d3448dd213145a2a870be83020657d9652c24e.
The hashes of src/gui/form_loader.asm, src/gui/settings_prefs.asm, src/gui/start_programs.asm and their 240 matching row hashes now bind that source.
Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 10 supersedes its preceding revision.

## Current integration correction (2026-10-31)

Start search aliases (rebased on SRC return 90299), source pins; source 03514672439c61b30c4592424540eee28ea24f03.
The hashes of src/gui/naming_picker.asm and their 15 matching row hashes now bind that source.
Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 11 supersedes its preceding revision.

## Current integration correction (2026-10-31)

Settings Apps refused-window words (root ruling on SRC 90368), source pins; source aec814baf49635c6cb70a1c5ac0ff260f1f18a6a.
The hashes of src/gui/settings_prefs.asm, src/gui/start_programs.asm and their 30 matching row hashes now bind that source.
Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 12 supersedes its preceding revision.

## Lock-card recovery words (2026-10-31)

Root 90461: message 4072 no longer names an owner-key service in Rescue, which does not exist. English and five
machine-authored translations change for this one record, with existing glyphs. IDs, eligibility and every other
text are unchanged. Peter's native-language evaluation is not claimed.

## Current integration correction (2026-11-01)

Accepted gallery e945ef1b4 restacked on eea377fc7;91019 permits unchanged behaviour without new review. Newer recovery words and catalog meanings retained; RES owns combined Calendar+gallery union pins.; source 073fce86bf0e773a2d7db306cc33d123a27ac4c2.
The hashes of src/gui/form_loader.asm, src/gui/img/img_core.asm, src/gui/start_programs.asm and their 277 matching row hashes now bind that source.
Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 13 supersedes its preceding revision.

## Current integration correction (2026-11-01)

Accepted calendar correction f75d556fc (SRC90263) is rebased on ADMIN91019 calendar/gallery union on 5116a23bd; source 5116a23bd2577f658e084f356ef2d95e1e4ac02f.
The Terminal source hash and its 173 matching row hashes now bind that source.
The Explorer source still matches its previous pin. Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 14 supersedes its preceding revision.

## Current integration correction (2026-11-01, Explorer entry)

The Explorer Start entry (root 91027) changed src/gui/form_loader.asm; its source hash and its 210 matching row hashes now bind that source at 0cd84b322.
Accepted catalog payloads, six-locale translations, IDs and eligibility are unchanged. Source-map revision 15 supersedes its preceding revision.

## Current integration correction (2026-10-31)

REMOVE UI for Settings Apps: start_programs.asm and settings_apps.frm changed; no catalog text; source a65ce8bdd72ec6eb33f960201066b1bfea1a03c4.
The hashes of src/gui/start_programs.asm and their 21 matching row hashes now bind that source.
Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 16 supersedes its preceding revision.

## Current integration correction (2026-10-31)

REMOVE UI: start_programs.asm arm-row helper; no catalog text; source 3a2d22e81f64f9add4eacc19efccd1b507843566.
The hashes of src/gui/start_programs.asm and their 21 matching row hashes now bind that source.
Accepted catalog payloads, six-locale
translations, IDs and eligibility are unchanged; only source provenance and its
generated closure change. Source-map revision 17 supersedes its preceding revision.

Decision42 (2026-11-02, Codex / rc-input-claude): source_sites revision18
refreshes only form_loader.asm current source and matching row pins for the
Allow this? inline consent title. Active catalog meanings, IDs, eligibility and
six-locale translations are unchanged. New form names and consent literals
remain untranslated English fallback; see docs/USER_FACING_NAMES.md. This does
not claim translated coverage or native-language review for those surfaces.

Command catalog (2026-11-02, Codex / rc-input-claude): source-sites revision19
refreshes help_view.asm and terminal_app.asm provenance after the shared Commands
page and native HELP operand route. Existing active messages, stable IDs, glyphs,
eligibility and six-locale meanings are unchanged. The generated Commands page
uses bounded escaped English metadata from tools/commands/commands.json; no
translated coverage or native-language review is claimed for this new surface.

## Help navigation source binding (2026-11-10)

The accepted Help navigation lifetime change bdab6695a refreshed the maintained
Help source hashes without rebinding the catalog schema. This repair binds the
catalog to that exact accepted site map and synchronizes the public catalog and
site map. The existing adjudication projection and generated catalog include
are refreshed, together with the input, manifest, recipe and output pins.
All 92 active messages, stable IDs, six-locale text, eligibility, glyph bytes
and compiler algorithms are unchanged. PCAT1 schema and artifact expectations
change with source provenance. Every source admission check remains in force.
This closes the Help binding regression; unrelated source-pin freshness and
native image/runtime localization evidence remain separate work.

## Offline Try guide (2026-11-10)

The two Help declarations append a Try section to First boot, with English messages
6045-6049 from the current Try/session, Console and installer sources at
9382d0d9e58632ffd5bcdc0a37901cc6f6c7027c. Existing eight page ordinals,
all earlier messages and translations, UI catalogs and glyph cells are preserved.
Other locales use the existing English fallback for these new instructions.
The guide describes temporary local Try, reading Help without a network,
standard raw/dd USB preparation, and the absent native OS-install action.
It does not claim that install inputs or an offline installation were exercised.
The source, recipe, manifest and generated include pins are refreshed through
the unchanged compiler and source admission checks.

## Current source snapshot refresh (2026-11-10)

ROOT ledger112511: accepted source-map revision20 now binds all 138 source files
to exact integration fe118066216e1f370944f07ede32ca6cd9899e5c. The 121 stale
file pins and matching row pins are refreshed with the accepted-map mode of
rcq38_adjudicate.py. Historical inventory, stable IDs, English, six-locale
texts, decisions, anchor statuses and eligibility are unchanged. The report,
catalog site digest, public source closure and generated catalog expectations
are rebound together; glyph bytes and compiler algorithms are unchanged.
This is source snapshot provenance, with no new literal adjudication, image
binding, native-language review or runtime localization claim.

## Accepted source snapshot refresh

ROOT112511 / reviewed tool112603: revision 21 binds exact accepted source snapshot 95b33ab7709d950b43171868496e093a3d99854b. Refreshed 3 file pins and their row pins; accepted IDs, English, translations, decisions, anchor statuses and eligibility are unchanged. Generated digests follow that snapshot; no runtime or new translation claim.

## Accepted source snapshot refresh

ROOT112511 / reviewed tool112603: revision 22 binds exact accepted source snapshot 5beca6416ae78b37670e031e00172601cb47309e. Refreshed 5 file pins and their row pins; accepted IDs, English, translations, decisions, anchor statuses and eligibility are unchanged. Generated digests follow that snapshot; no runtime or new translation claim.

## Current Help source binding (2026-11-11)

The public UI catalog and source-site map now copy the maintained declarations
accepted in integration f13857d9d (REL Help source binding). The Help source file
and literal row bind the accepted current Help implementation; stable message
IDs, English, translations and eligibility stay unchanged. The unchanged public
compiler reproduces the already accepted native catalog include byte for byte.
SOURCES.json and the manifest, recipe and output pins are refreshed together.
This repairs public regeneration; it adds no runtime or translation claim.

## Bounded desktop power failure labels (2026-11-11)

The public catalog and source-site map include fifteen critical English cause
labels (message IDs 4610-4624) for the bounded desktop power refusal mapper.
Seven raw power reason strings remain machine contracts and are ineligible for
translation. Existing message IDs, English and translations are retained.
The fifteen new labels use the existing English fallback in other locales;
this source change supplies no new translations or localized runtime evidence.

The catalog and source-site SHA-256 entries in SOURCES.json, the manifest and
recipe pins, and the generated catalog expectation are refreshed together.
The unchanged public compiler reproduces the accepted catalog include and all
six PCAT1 files from these admitted inputs. Glyph bytes, Unicode and font
inputs, licenses, helper algorithms and all other manifest entries are unchanged.

## Managed shutdown dialog outcome freshness (2026-11-11)

The source-site current hashes now cover the read-only managed shutdown
terminal status consumer in Start and its bounded label projection. Existing
message IDs, decisions, English, translations, widths and glyphs are unchanged.
The site digest, public mirrors, manifest and recipe pins and generated catalog
are refreshed together by the unchanged compiler. This supplies no translation,
widget rendering, hardware recovery or power-transition observation.

## Explorer occupied-volume refusal source freshness (2026-11-11)

The current source hash now covers the accepted Explorer occupied NTFS volume
refusal in form_loader.asm. Existing message IDs, decisions, English,
translations, widths and glyphs are unchanged. The source-site digest, public
mirrors, manifest and recipe pins and generated catalog are refreshed together
by the unchanged compiler. This supplies no translation, widget rendering,
storage recovery or runtime observation.

## Managed terminal cause freshness (2026-11-11)

The source-site current hashes now cover the read-only managed terminal
pre-commit cause projection in power_exec. Existing
message IDs, decisions, English, translations, widths and glyphs are unchanged.
The site digest, public mirrors, manifest and recipe pins and generated catalog
are refreshed together by the unchanged compiler. This supplies no translation,
widget rendering, hardware recovery or power-transition observation.

## Managed desktop cancellation freshness (2026-11-11)

The source-site current hashes now cover original watched Start cancellation
and the same-owner/full64 pre-commit boundary in power_exec. Existing
message IDs, decisions, English, translations, widths and glyphs are unchanged.
The site digest, public mirrors, manifest and recipe pins and generated catalog
are refreshed together by the unchanged compiler. This supplies no translation,
widget rendering, hardware recovery or power-transition observation.

## Restart refusal offline state (2026-11-12)

The current source-site hash covers the original restart refusal paths and
one additive machine-contract wire token for an actually offline NVMe disk.
Its historical-inventory anchor is source_drift; it is not runtime eligible.
All existing IDs, English, translations, widths and glyphs remain unchanged.
The existing public Disk offline until restart message is reused. The site
digest, mirrors, manifest/recipe pins and generated catalog are refreshed by
the unchanged compiler. This supplies no physical power or recovery proof.

## Bounded desktop power failure label translations (2026-11-13)

The fifteen critical power failure cause labels (message IDs 4610-4624) gain
machine-authored de, es, fr, ja and zh-Hans text; 4611 and 4612 reuse the
accepted translations of the identical English messages 1125 and 1126. All
other message IDs, English, translations, widths and glyph inputs are
unchanged. The catalog entry in SOURCES.json, the manifest and recipe pins and
the generated outputs are refreshed together by the unchanged compiler. This
supplies no localized widget rendering, native-language evaluation or power
observation; back translation and security review remain owed.

Review revision (2026-11-13): after rc-input back translation (LEDGER 118728,
R1), the French text of 4613 and 4619 names the pending writes, as the
accepted French 1066 does, instead of "vidage du disque". No other string
changes.

## Staged-owner continuation texts (2026-11-15)

T5-9: message 4071 ("Owner staged; restart to apply") is retired and kept as
a reserved tombstone, because the staged credential now applies without a
restart. Three critical security/consent messages are added (IDs 4645-4647):
two lock-card notices for a change or setup that did not apply, and the
first-owner disclosure that, until PaOS next starts, other systems on the PC
can see a protected copy of the new password check. They have
machine-authored de, es, fr, ja and zh-Hans text, read by rc-sec and
back-translated by rc-input as drafts. Current source pins are refreshed at
the base commit. All other message IDs, English, translations and widths are
unchanged, and the glyph output is unchanged. This supplies no native
rendering proof or native-language evaluation.
