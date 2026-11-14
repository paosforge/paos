/* SPDX-License-Identifier: Apache-2.0
 * PaOS single-code-point grayscale renderer. No shaping or font discovery.
 * For ASCII at integral origin this is byte-equivalent to the original
 * Pillow 12.1.0 / FreeType 2.14.1 recipe; see SOURCE.md and the independent KAT.
 */
#include <stdio.h>
#include <ft2build.h>
#include FT_FREETYPE_H

int main(int argc, char **argv) {
    FT_Library library;
    FT_Face face;
    FT_Int major, minor, patch;
    if (argc != 2 || FT_Init_FreeType(&library)) return 2;
    FT_Library_Version(library, &major, &minor, &patch);
    if (major != 2 || minor != 14 || patch != 1) return 3;
    if (FT_New_Face(library, argv[1], 0, &face) ||
        FT_Select_Charmap(face, FT_ENCODING_UNICODE) ||
        FT_Set_Pixel_Sizes(face, 0, 15)) return 4;
    for (unsigned cp = 32; cp <= 126; ++cp) {
        unsigned char cell[9 * 19] = {0};
        if (!FT_Get_Char_Index(face, cp) || FT_Load_Char(face, cp, FT_LOAD_RENDER)) return 5;
        FT_GlyphSlot s = face->glyph;
        FT_Bitmap *b = &s->bitmap;
        if (b->pixel_mode != FT_PIXEL_MODE_GRAY || b->num_grays != 256 ||
            b->pitch < 0 || b->pitch < (int)b->width || b->rows > 64 || b->width > 64) return 6;
        for (unsigned y = 0; y < b->rows; ++y) {
            for (unsigned x = 0; x < b->width; ++x) {
                int ox = (int)x + s->bitmap_left;
                int oy = (int)y + 14 - s->bitmap_top;
                if (ox >= 0 && ox < 9 && oy >= 0 && oy < 19)
                    cell[oy * 9 + ox] = b->buffer[y * b->pitch + x];
            }
        }
        if (fwrite(cell, 1, sizeof(cell), stdout) != sizeof(cell)) return 7;
    }
    FT_Done_Face(face);
    FT_Done_FreeType(library);
    return fflush(stdout) ? 8 : 0;
}
