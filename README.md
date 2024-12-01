# Asuswrt-Configs-Deobfuscator

Tool to deobfuscate Asuswrt configuration files.

**Based on the project**: [BigNerd95/Asuswrt-Configs-Deobfuscator](https://github.com/BigNerd95/Asuswrt-Configs-Deobfuscator)

---

## Supported Models

- AX86U
- AC86U
- Legacy models (N55U, AC55U)

---

## Installation

Clone the repository and ensure you have Python 3 installed.

---

## Usage Examples

### Enable Debug Mode

Use the `--debug` flag to enable detailed logging for debugging purposes. Logs will include additional information about file processing, header parsing, and algorithm behavior.

Example:
```
./awrtconf.py --debug decode -i Settings_AX86U.CFG -o Decoded_AX86U.CFG -r 2
```

Sample output with `--debug`:
```
2024-12-01 13:13:48,460 - INFO - Decoding file Settings_AX86U.CFG with Randkey=2
2024-12-01 13:13:48,460 - DEBUG - Reading file
2024-12-01 13:13:48,461 - DEBUG - File read successfully, size: 76808 bytes
2024-12-01 13:13:48,467 - DEBUG - Writing file
2024-12-01 13:13:48,467 - DEBUG - File written successfully, size: 76800 bytes
2024-12-01 13:13:48,467 - INFO - Decoded file saved to Decoded_AX86U.CFG
```

Logs are saved to `asuswrt_deobfuscator.log` in the current directory.

---

## Usage Commands

### Info

Get configuration file details, including header information and potential issues with the `RandKey`.

```
./awrtconf.py info -i Settings_AX86U.CFG
```

### Dump

Dump the configuration file into JSON format. **Do NOT modify the `PROFILE` value in the JSON file**.

```
./awrtconf.py dump -i Settings_AX86U.CFG -o Settings_AX86U.json
```

### Pack

Pack a JSON configuration back into a `.CFG` file.

```
./awrtconf.py pack -i Settings_AX86U.json -o Settings_AX86U_new.CFG
```

### Pack with Plaintext

Force packing the JSON configuration into plaintext mode. This avoids potential issues with the obfuscation algorithm.

```
./awrtconf.py pack -i Settings_AX86U.json -o Settings_AX86U_plain.CFG -p
```

### Test RandKeys

Test the file with various `RandKey` values to find a readable configuration. This command analyzes the file using a range of recommended keys and outputs the first readable portion for each key.

```
./awrtconf.py test -i Settings_AX86U.CFG
```

Sample output:
```
2024-12-01 13:09:57,012 - INFO - Testing recommended Randkeys: [0, 1, 2, 3, 4, 14, 15, ...]
2024-12-01 13:09:57,025 - INFO - Randkey=2: Decoded body: 0:aa2g=0x7...
2024-12-01 13:09:57,031 - INFO - Randkey=3: Decoded body: 1;bb3h>1y...
```

Look for a human-readable result (e.g., `RandKey=2` in this case).

### Decode with a Specific RandKey

After identifying the appropriate `RandKey`, use the `decode` command to fully decode the configuration file.

```
./awrtconf.py decode -i Settings_AX86U.CFG -o Decoded_AX86U.CFG -r 2
```

Verify the decoded file contents:
```
strings Decoded_AX86U.CFG
```

---

## Header Structure

### Plaintext `.CFG`

| Size (byte) | Type           | Name      | Comment                                    |
|-------------|----------------|-----------|--------------------------------------------|
| 4           | Char array     | Profile   | Profile name: HDR1                         |
| 4           | Unsigned Int   | Body Size | Aligned to the next KB (e.g., 31744 bytes) |

### Obfuscated `.CFG`

| Size (byte) | Type           | Name      | Comment                                    |
|-------------|----------------|-----------|--------------------------------------------|
| 4           | Char array     | Profile   | Profile name: HDR2, AX86U, or AC86U        |
| 3           | Unsigned Int   | Body Size | Aligned to the next KB (e.g., 31744 bytes) |
| 1           | Unsigned Int   | RandKey   | Random key in the range [0, 29]            |

---

## Obfuscation Algorithm

The body of the `.CFG` file is obfuscated using a weak and flawed algorithm.

### Save Backup

For each byte of the NVRAM:
```
if byte == 0x00:
byte <- 0xFD or 0xFE or 0xFF
else:
byte <- 0xFF + RandKey - byte
```

### Restore Backup

For each byte of the `.CFG` file:
```
if byte == 0xFD or 0xFE or 0xFF:
byte <- 0x00
else:
byte <- 0xFF + RandKey - byte
```

---

## Algorithm Bugs

### Byte Overflow

Bytes with values less than the `RandKey` may overflow and be misinterpreted.

### Null Byte Collision

When a `Null Byte (0x00)` is obfuscated, it is replaced with `0xFD`, `0xFE`, or `0xFF`. This can cause collisions with valid values if the `RandKey` is poorly chosen.

### Recommended RandKeys

To minimize data loss:
- Use a `RandKey` in the range `[0, 4]` or `[14, 29]`.
- The best `RandKey` is `0`, as it only loses two non-printable characters (`0x01` and `0x02`).

---

## Reference

- Original Project: [BigNerd95/Asuswrt-Configs-Deobfuscator](https://github.com/BigNerd95/Asuswrt-Configs-Deobfuscator)
- ASUS Source Code: [ASUS nvram.c](https://github.com/RMerl/asuswrt-merlin.ng/blob/master/release/src/router/nvram/nvram.c#L546)