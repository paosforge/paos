def emit_w(name, arr, f):
    f.write(name + ":\n")
    for k in range(0, len(arr), 16):
        f.write("    dw " + ",".join(str(x & 0xFFFF) for x in arr[k:k+16]) + "\n")
def emit_b(name, arr, f):
    f.write(name + ":\n")
    for k in range(0, len(arr), 16):
        f.write("    db " + ",".join("0x%02X" % (x & 0xFF) for x in arr[k:k+16]) + "\n")

