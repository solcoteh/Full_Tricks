# Forensic ✅

## binwalk ✅
```bash
binwalk -e <file>
binwalk -Me <file> # recursively
```
```bash
binwalk flag2of2-final.pdf

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 50 x 50, 8-bit/color RGBA, non-interlaced
914           0x392           PDF document, version: "1.4"
1149          0x47D           Zlib compressed data, default compression
```
```bash
binwalk --dd='.*' flag2of2-final.pdf
binwalk --dd='png' flag2of2-final.pdf
binwalk --dd='pdf' flag2of2-final.pdf
```
```bash
dd if=flag2of2-final.pdf of=output_image.png bs=1 count=914 # Extract png
dd if=flag2of2-final.pdf of=output_image.zlib skip=1149 bs=1 # extract just zlib 
dd if=flag2of2-final.pdf of=output_image.pdf skip=914 bs=1  # extract pdf full
dd if=flag2of2-final.pdf of=output_image.pdf skip=914 bs=1 count=$((1149-914)) # extract just pdf without data
```

