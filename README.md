# Asuswrt-Configs-Deobfuscator
Tool to deobfuscate asuswrt configs files

---

## Usage examples

### Info
`./awrtconf.py info -i Settings_DSL-N55U.CFG`

### Dump
`./awrtconf.py dump -i Settings_DSL-N55U.CFG -o Settings_DSL-N55U.json`

The dump is in json format, do NOT modify PROFILE value.

### Pack
`./awrtconf.py pack -i Settings_DSL-N55U.json -o Settings_DSL-N55U_new.CFG`

### Pack forcing plaintext
`./awrtconf.py pack -i Settings_DSL-N55U.json -o Settings_DSL-N55U_plain.CFG -p`

All firmware support the plaintext file for restoring, so you can backup, dump, edit and then pack as plaintext.

---

## Header structure
The header is 8 bytes long and it's in little endian format

###### Plaintext CFG:

| Size (byte)  | Type | Name | Comment |
| :----------: | ---- | ---- | ------- |
| 4 | Char array  | Profile | Profile name: HDR1 |
| 4 | Unsigned Int | Body Size | Aligned to next KB (e.g. 31744 (0x00007c00)) |

###### Obfuscated CFG:

| Size (byte)  | Type | Profile | Comment |
| :----------: | ---- | ---- | ------- |
| 4 | Char array | Profile | Profile name: HDR2 or N55U or AC55U |
| 3 | Unsigned Int | Body size | Aligned to next KB (e.g. 31744 (0x00007c00)) |
| 1 | Unsigned Int | Randkey | Random number in interval [0, 29], used to obfuscate the file body |

---

## Obfuscation Algorithm
The body of the config file is the nvram content obfuscated with a weak and bugged algorithm.

### Pseudocode

###### Save backup:
For each byte of the nvram:
```
if byte = 0x00
	byte <- 0xFD or 0xFE or 0xFF
else
	byte <- 0xFF + randkey - byte
```

###### Restore backup:
For each byte of CFG file:
```
if byte = 0xFD or 0xFE or 0xFF
	byte <- 0x00
else
	byte <- 0xFF + randkey - byte;
```

---

### Algorithm bugs
##### Byte overflow

All the bytes with a value less than randkey may be lost.

###### Example:
If the randkey is 18 (0x12) and we have a Line Feed char 0x0A (10) in the nvram:
```
0xFF + 0x12 - 0x0A -> 0x0107 (byte overflow)
255  +  18  -  10  ->  263
```
Which become 0x07 (7) when written to CFG file as single byte.

If now we try to restore the backup, when the algorithm try to deobfuscate 0x07:
```
0xFF + 0x12 - 0x07 -> 0x010A
255  +  18  -  7   ->  266
```
We need to **subtract 0x0100 (256)** to get back 0x0A (10)

This is the why in my tool I added this condition:
```
if byte < randkey:
  byte <- 0xFF + randkey - byte - 0x0100
```

-

##### Null Byte collision

All the bytes with a value equals to: 
- randkey 
- randkey + 1
- randkey + 2

are lost.

This is due to the fact that the algorithm randomly write:
- 0xFF (255) 
- 0xFE (254)
- 0xFD (253)

when there is a **Null Byte (0x00)** to obfuscate and can make a collision with other value based on the randkey.

###### Example:
If the randkey is 0x09, when the algorithm tries to obfuscate a:

| Char Name | Escape | ASCII hex | Obfuscation |
| ----------| :----: | :-------: | ----------- |
| Horizontal Tab| \t | 0x09 | 0xFF + 0x09 - 0x09 -> **0xFF**  (collision with 0x00) |
| Line Feed     | \n | 0x0A | 0xFF + 0x09 - 0x0A -> **0xFE**  (collision with 0x00) |
|Vertial Tab    |    | 0x0B | 0xFF + 0x09 - 0x0B -> **0xFD**  (collision with 0x00) |
 
When the algorithm tries to deobfuscate the CFG file, it **can't distinguish a Null Byte from an Horizontal Tab, Line Feed or Vertial Tab** due to this part of the algorithm:
```
if byte = 0xFD or 0xFE or 0xFF
	byte = 0x00
...
```
So we have lost 3 bytes.

There is no way to completely fix this collision.

I can only advice to remake the backup until you get a randkey less than 5 (0x05) or greater than 13 (0x0D).

The **best value for randkey is 0x00**, because due to collision with 0x00, we only lose 0x01 and 0x02, so **only 2 values instead of 3 are lost**, then they are not printable chars, so they are not often used.


