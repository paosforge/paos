/* Read-only, target-neutral BootCurrent -> GPT partition/EFI path parser. */
#include "boot_route.h"

#include <stdint.h>
#include <string.h>

static uint16_t rd16(const uint8_t *p) {
    return (uint16_t)p[0] | (uint16_t)((uint16_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
           (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static uint64_t rd64(const uint8_t *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; ++i) value |= (uint64_t)p[i] << (i * 8);
    return value;
}

static int any_nonzero(const uint8_t *p, size_t size) {
    uint8_t any = 0;
    for (size_t i = 0; i < size; ++i) any |= p[i];
    return any != 0;
}

static int ascii_path_equal(const char *path, const char *expected) {
    if (!path) return 0;
    for (size_t i = 0; ; ++i) {
        unsigned char c = (unsigned char)path[i];
        if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
        if (c != (unsigned char)expected[i]) return 0;
        if (!c) return 1;
    }
}

const char *prc_route_manager(const char *efi_path) {
    if (ascii_path_equal(efi_path, "\\EFI\\PAOS\\SB\\SHIMX64.EFI"))
        return "EFI/PaOS/sb/grubx64.efi";
    /* HP's existing canonical firmware entry uses this relocated MS shim.
     * Do not borrow the preserved sb/ Manager for the relocated chain. */
    if (ascii_path_equal(efi_path, "\\EFI\\PAOS\\PAOS64.EFI"))
        return "EFI/PaOS/grubx64.efi";
    if (ascii_path_equal(efi_path, "\\EFI\\PAOSCHAIN\\SHIMX64.EFI"))
        return "EFI/PAOSCHAIN/grubx64.efi";
    return NULL;
}

static int parse_boot_route(const uint8_t *current, size_t current_size,
                         const uint8_t *option, size_t option_size,
                         uint16_t *boot_number, uint8_t part_guid[16],
                         char efi_path[PRC_BOOT_PATH_SIZE], int common_usb) {
    if (boot_number) *boot_number = 0;
    if (part_guid) memset(part_guid, 0, 16);
    if (efi_path) memset(efi_path, 0, PRC_BOOT_PATH_SIZE);
    if (!current || !option || !boot_number || !part_guid || !efi_path ||
        current_size != 6 || option_size < 20 || option_size > 4096 ||
        rd32(current) != 6 || rd32(option) != 7 ||
        rd32(option + 4) != 1) return -1;
    uint16_t number = rd16(current + 4);
    size_t path_bytes = rd16(option + 8);
    size_t cursor = 10;
    unsigned chars = 0;
    while (cursor + 1 < option_size && chars <= 128) {
        uint16_t c = rd16(option + cursor);
        cursor += 2;
        if (!c) break;
        if (c < 0x20 || c > 0x7e) return -1;
        ++chars;
    }
    if (!chars || chars > 128 || cursor > option_size ||
        rd16(option + cursor - 2) != 0 || path_bytes < 4 ||
        path_bytes > option_size - cursor) return -1;
    /* EFI_LOAD_OPTION optional data follows the declared device-path list.
     * Lenovo's real signed-shim and Ubuntu options both carry it. Ignore it
     * strictly as opaque non-authoritative bytes, never as a route node. */
    size_t end = cursor + path_bytes;
    int found_hd = 0, found_file = 0, found_usb = 0, ended = 0;
    uint8_t guid[16] = {0};
    char path[PRC_BOOT_PATH_SIZE] = {0};
    while (cursor < end) {
        if (end - cursor < 4) return -1;
        uint8_t type = option[cursor], subtype = option[cursor + 1];
        size_t length = rd16(option + cursor + 2);
        if (length < 4 || length > end - cursor) return -1;
        const uint8_t *node = option + cursor;
        cursor += length;
        if (type == 4 && subtype == 1) {
            if (found_hd || length != 42 || !rd32(node + 4) ||
                !rd64(node + 8) || !rd64(node + 16) ||
                !any_nonzero(node + 24, 16) ||
                node[40] != 2 || node[41] != 2) return -1;
            if (common_usb && (!found_usb || rd32(node + 4) != 1)) return -1;
            memcpy(guid, node + 24, 16);
            found_hd = 1;
        } else if (type == 4 && subtype == 4) {
            if (common_usb) return -1;
            if (found_file || length < 8 || (length & 1)) return -1;
            size_t letters = (length - 4) / 2;
            if (letters < 2 || letters >= PRC_BOOT_PATH_SIZE ||
                node[4] != '\\' || node[5] ||
                node[length - 2] || node[length - 1]) return -1;
            for (size_t i = 0; i < letters - 1; ++i) {
                uint8_t c = node[4 + i * 2];
                if (node[5 + i * 2] || c < 0x20 || c > 0x7e ||
                    c == '/' || (c == '.' && i + 1 < letters - 1 &&
                    node[4 + (i + 1) * 2] == '.')) return -1;
                path[i] = (char)c;
            }
            found_file = 1;
        } else if (type == 0x7f) {
            if (subtype != 0xff || length != 4) return -1;
            if (cursor != end) {
                /* Saved MSI firmware appends this exact vendor annotation
                 * and another End after the USB HD path's End. It has no
                 * route authority. Accept only these retained bytes, not a
                 * second disk, FilePath or arbitrary extra instance. */
                static const uint8_t suffix[28] = {
                    1,4,24,0,0xef,0x47,0x64,0x2d,0xc9,0x3b,0xa0,0x41,
                    0xac,0x19,0x4d,0x51,0xd0,0x1b,0x4c,0xe6,9,4,0,0,
                    0x7f,0xff,4,0,
                };
                if (!common_usb || end - cursor != sizeof(suffix) ||
                    memcmp(option + cursor, suffix, sizeof(suffix))) return -1;
                cursor = end;
            }
            ended = 1;
        } else if (common_usb) {
            /* Only the saved hardware-prefix/USB/HD shape. In particular an
             * internal HD, URI, vendor node or a second instance cannot be
             * reinterpreted as a removable COMMON chain. */
            if (found_hd || found_usb) return -1;
            if (type == 3 && subtype == 5 && length == 6) found_usb = 1;
            else if (!((type == 2 && subtype == 1 && length == 12) ||
                       (type == 1 && subtype == 1 && length == 6))) return -1;
        }
        if (ended) break;
    }
    if (!ended || !found_hd || cursor != end ||
        (common_usb ? (!found_usb || found_file) : !found_file)) return -1;
    *boot_number = number;
    memcpy(part_guid, guid, 16);
    memcpy(efi_path, path, PRC_BOOT_PATH_SIZE);
    return 0;
}

int prc_parse_boot_route(const uint8_t *current, size_t current_size,
                         const uint8_t *option, size_t option_size,
                         uint16_t *boot_number, uint8_t part_guid[16],
                         char efi_path[PRC_BOOT_PATH_SIZE]) {
    return parse_boot_route(current, current_size, option, option_size,
                            boot_number, part_guid, efi_path, 0);
}

int prc_parse_manager_route(const uint8_t *current, size_t current_size,
                            const uint8_t *option, size_t option_size,
                            uint16_t *boot_number, uint8_t part_guid[16],
                            const char **manager) {
    if (manager) *manager = NULL;
    if (!manager) return -1;
    char path[PRC_BOOT_PATH_SIZE];
    if (!parse_boot_route(current, current_size, option, option_size,
                          boot_number, part_guid, path, 0)) {
        *manager = prc_route_manager(path);
        if (*manager) return 0;
        if (boot_number) *boot_number = 0;
        if (part_guid) memset(part_guid, 0, 16);
        return -2; /* Well-formed explicit path outside supported PaOS routes. */
    } else if (!parse_boot_route(current, current_size, option, option_size,
                                 boot_number, part_guid, path, 1)) {
        *manager = "EFI/PAOSCHAIN/grubx64.efi";
        return 0;
    }
    if (boot_number) *boot_number = 0;
    if (part_guid) memset(part_guid, 0, 16);
    return -1;
}

int prc_partuuid_matches(const uint8_t part_guid[16],
                         const char *partuuid, size_t partuuid_size) {
    static const uint8_t order[16] = {
        3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15,
    };
    static const char hex[] = "0123456789abcdef";
    if (!part_guid || !partuuid || partuuid_size != 36) return 0;
    size_t pos = 0;
    for (unsigned i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            if (partuuid[pos++] != '-') return 0;
        }
        uint8_t value = part_guid[order[i]];
        char hi = partuuid[pos++], lo = partuuid[pos++];
        if (hi >= 'A' && hi <= 'F') hi += 'a' - 'A';
        if (lo >= 'A' && lo <= 'F') lo += 'a' - 'A';
        if (hi != hex[value >> 4] || lo != hex[value & 15]) return 0;
    }
    return pos == 36;
}

int prc_os_boot_option(const uint8_t *option, size_t size, int windows,
                       uint8_t hd[42]) {
    if (!option || !hd || (windows != 0 && windows != 1)) return -1;
    memset(hd, 0, 42);
    if (size < 12 || size > 4096 || rd32(option) != 7) return -1;
    if (!(rd32(option + 4) & 1)) return 0;
    const char *label = windows ? "WINDOWS BOOT MANAGER" : "UBUNTU";
    size_t cursor = 10;
    for (size_t i = 0; ; ++i, cursor += 2) {
        if (size - cursor < 2) return -1;
        unsigned c = rd16(option + cursor);
        if (c >= 'a' && c <= 'z') c -= 'a' - 'A';
        if (c != (unsigned char)label[i]) return 0;
        if (!c) { cursor += 2; break; }
    }
    size_t path_bytes = rd16(option + 8);
    if (path_bytes < 4 || path_bytes > size - cursor) return -1;
    size_t end = cursor + path_bytes;
    int found_hd = 0, kind = 0;
    while (cursor < end) {
        if (end - cursor < 4) return -1;
        const uint8_t *node = option + cursor;
        size_t length = rd16(node + 2);
        if (length < 4 || length > end - cursor) return -1;
        cursor += length;
        if (node[0] == 0x7f)
            return node[1] == 0xff && length == 4 && cursor == end &&
                   found_hd && kind ? kind : -1;
        /* A FilePath must be the final non-END node, as in the Manager. */
        if (kind) return -1;
        if (node[0] == 4 && node[1] == 1) {
            if (found_hd || length != 42 || !rd32(node + 4) ||
                !rd64(node + 8) || !rd64(node + 16) ||
                !any_nonzero(node + 24, 16) || node[40] != 2 || node[41] != 2)
                return -1;
            memcpy(hd, node, 42); found_hd = 1;
        } else if (node[0] == 4 && node[1] == 4) {
            if (!found_hd || length < 8 || (length & 1)) return -1;
            char path[PRC_BOOT_PATH_SIZE] = {0};
            size_t letters = (length - 4) / 2;
            if (letters >= sizeof(path) || rd16(node + length - 2)) return -1;
            for (size_t i = 0; i < letters - 1; ++i) {
                unsigned c = rd16(node + 4 + 2 * i);
                if (c < 0x20 || c > 0x7e) return -1;
                path[i] = (char)c;
            }
            if (windows && ascii_path_equal(path, "\\EFI\\MICROSOFT\\BOOT\\BOOTMGFW.EFI"))
                kind = 1;
            else if (!windows && ascii_path_equal(path, "\\EFI\\UBUNTU\\SHIMX64.EFI"))
                kind = 1;
            else if (!windows && ascii_path_equal(path, "\\EFI\\UBUNTU\\GRUBX64.EFI"))
                kind = 2;
            else return -1;
        }
    }
    return -1;
}
