# Extended sequential JPEG ingress

The native decoder admits SOF1 Huffman extended-sequential frames with 8-bit
samples and 8-bit quantizers. The existing gray, YCbCr 444/420/422/440/411,
explicit Adobe RGB, CMYK and YCCK profiles retain their limits and metadata
rules. SOF1 permits DC and AC Huffman destinations 0 through 3 independently.
The SOF0 destination limit remains 0 through 1.

Every SOF1 image uses the existing bounded, SHA-bound private source and whole
coefficient frame. Full interleaved, component-separated and ordered subset
scans use sequential coverage: each component appears exactly once, with
Ss=0, Se=63 and Ah=Al=0. Progressive EOB-run alphabets remain invalid here.
Pixels publish only after all entropy, component coverage and exact EOI pass.
Restart intervals, per-scan table definitions, Exif orientation, common image
dispatch, cache retirement and allocation failure use the existing paths.

This is an explicit subset. Twelve-bit samples, 16-bit quantizers, arithmetic,
lossless and hierarchical coding remain unsupported. The existing dimension,
pixel, source-byte and coefficient-frame caps are unchanged.

The format basis is [ITU-T T.81](https://www.w3.org/Graphics/JPEG/itu-t81.pdf),
B.2.2 through B.2.4. SOF0/SOF1 8-bit full-spectrum Huffman scans share their
coefficient syntax. Tests change only frame markers and table destinations in
independently encoded fixtures, compare exact Python entropy/cosine-reference
RGBA, and separately verify libjpeg accepts the SOF1 bytes. This is native
codec evidence, with no app, display or hardware acceptance claim.
