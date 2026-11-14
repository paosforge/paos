# ---- ISO 11172-3 scalefactor band index, 44100 Hz ----
SFB_LONG = [0,4,8,12,16,20,24,30,36,44,52,62,74,90,110,134,162,196,238,288,342,418,576]
SFB_SHORT = [0,4,8,12,16,22,30,40,52,66,84,106,136,192]  # widths ×3 windows

INV_SQRT2 = 1.0/math.sqrt(2.0)

# Alias-reduction butterfly coefficients (ISO table)
CI = [-0.6, -0.535, -0.33, -0.185, -0.095, -0.041, -0.0142, -0.0037]
CS = [1.0/math.sqrt(1.0+c*c) for c in CI]
CA = [c/math.sqrt(1.0+c*c) for c in CI]


