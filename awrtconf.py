#!/usr/bin/env python3

# based on Asuswrt Configs Deobfuscator by BigNerd95

from argparse import ArgumentParser, FileType
from struct import pack, unpack
from random import randint
import json
import sys
import logging

LOG_FILE = "asuswrt_deobfuscator.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),  # Логи в файл
        logging.StreamHandler(sys.stdout),  # Логи в консоль
    ],
)

validProfiles = [b'HDR1', b'HDR2', b'N55U', b'AC55U']

class Object(object):
    pass

def suggest_randkey():
    return [key for key in range(30) if key <= 4 or key >= 14]

def read_file(input_file):
    logging.debug("Reading file")
    try:
        file_data = input_file.read()
        input_file.close()
        logging.debug("File read successfully, size: %d bytes", len(file_data))
        return file_data
    except Exception as e:
        logging.error("Error reading file: %s", e)
        sys.exit(1)

def write_file(output_file, file_data):
    logging.debug("Writing file")
    try:
        output_file.write(file_data)
        output_file.close()
        logging.debug("File written successfully, size: %d bytes", len(file_data))
    except Exception as e:
        logging.error("Error writing file: %s", e)
        sys.exit(1)

def split_file(file_data):
    return file_data[:8], file_data[8:]

def check_lost_ascii(body_data, randkey):
    lost_chars = [randkey, randkey + 1, randkey + 2]
    for char in lost_chars:
        if char in body_data:
            logging.warning("Detected lost ASCII char (0x%x) in configuration body!", char)

def warning_info_loss(randkey):
    logging.warning(
        "Lost ASCII chars: %d (0x%x), %d (0x%x), %d (0x%x)",
        randkey, randkey, randkey + 1, randkey + 1, randkey + 2, randkey + 2
    )
    logging.warning(
        "If you used these chars in your configuration, please remake the backup "
        "with a different randkey or inspect the file for potential errors."
    )
    logging.warning(
        "Recommended randkey values: %s", suggest_randkey()
    )

def conf2jsonFile(output_file, body_data, profile):
    logging.debug("Converting configuration to JSON")
    string_array = str(body_data, 'ascii').split('\x00')
    jsonConf = {'PROFILE': profile, 'SETTINGS': {}}

    for string in string_array:
        if len(string) > 0:
            keyValue = string.split('=', 1)
            if len(keyValue) == 2:
                jsonConf['SETTINGS'][keyValue[0]] = keyValue[1]

    json.dump(jsonConf, output_file, indent=4, sort_keys=True)
    logging.debug("Configuration dumped to JSON")
    output_file.close()

def jsonFile2Conf(input_file):
    try:
        logging.debug("Parsing JSON configuration file")
        jsonConf = json.load(input_file)
    except Exception as e:
        logging.error("Error parsing JSON file: %s", e)
        sys.exit(1)
    else:
        input_file.close()
        profile = jsonConf['PROFILE']
        buff = bytearray()

        for key, value in sorted(jsonConf['SETTINGS'].items()):
            buff.extend(bytes(key, 'ascii') + b'=' + bytes(value, 'ascii') + b'\0')

        buff.extend(bytearray(1024 - len(buff) % 1024))  # Align to next KB
        logging.debug("Configuration converted back to binary")
        return buff, profile

def deobfuscate_body(body_data, randkey):
    logging.debug("Deobfuscating body with randkey=%s", randkey)
    body_data = bytearray(body_data)
    offset = 0xFF + randkey

    for i in range(len(body_data)):
        if body_data[i] >= 0xFD:
            body_data[i] = 0x00
        elif body_data[i] < randkey:
            body_data[i] = offset - body_data[i] - 0x0100
        else:
            body_data[i] = offset - body_data[i]

    return body_data

def obfuscate_body(body_data, randkey):
    logging.debug("Obfuscating body with randkey=%s", randkey)
    body_data = bytearray(body_data)
    offset = 0xFF + randkey

    for i in range(len(body_data)):
        if body_data[i] == 0x00:
            body_data[i] = 0xFD + randint(0, 2)
        elif body_data[i] < randkey:
            body_data[i] = offset - body_data[i] - 0x0100
        else:
            body_data[i] = offset - body_data[i]

    return body_data

def parse_header(header_data):
    logging.debug("Parsing header: %s", header_data)
    if len(header_data) == 8:
        unpacked_header = unpack('<4sI', header_data)
        if unpacked_header[0] in validProfiles:
            parsedHeader = Object()
            parsedHeader.profile = str(unpacked_header[0], 'ascii')

            if parsedHeader.profile == 'HDR1':
                parsedHeader.bodylength = unpacked_header[1]
            else:
                parsedHeader.bodylength = unpacked_header[1] & 0x00FFFFFF
                parsedHeader.randkey = unpacked_header[1] >> 24

            return parsedHeader
        else:
            logging.error("Unknown header: %s", unpacked_header[0])
            sys.exit(1)
    else:
        logging.error("File too short: length=%d", len(header_data))
        sys.exit(1)

def create_header(length, profile, randkey):
    logging.debug("Creating header with profile=%s, length=%s, randkey=%s", profile, length, randkey)
    profile = bytes(profile, 'ascii')
    if profile in validProfiles:
        if profile != b'HDR1':
            length = (randkey << 24) | length
        return pack('<4sI', profile, length)
    else:
        logging.error("Unknown profile: %s", profile)
        sys.exit(1)

def print_info(header_info, isBackup):
    logging.info("Header Info: Profile=%s, Body Length=%s bytes", header_info.profile, header_info.bodylength)
    if header_info.profile != 'HDR1':
        logging.info("Randkey=%s", header_info.randkey)
        if isBackup:
            warning_info_loss(header_info.randkey)

def conf_pack(input_file, output_file, plaintext):
    logging.info("Packing configuration from file: %s", input_file.name)
    body_data, profile = jsonFile2Conf(input_file)
    randkey = 0
    if plaintext:
        profile = 'HDR1'
    if profile != 'HDR1':
        randkey = randint(0, 29)
        body_data = obfuscate_body(body_data, randkey)
    header_data = create_header(len(body_data), profile, randkey)
    write_file(output_file, header_data + body_data)
    logging.info("Configuration packed successfully into file: %s", output_file.name)

def conf_dump(input_file, output_file):
    logging.info("Dumping configuration to JSON")
    file_data = read_file(input_file)
    header_data, body_data = split_file(file_data)
    header_info = parse_header(header_data)
    print_info(header_info, isBackup=True)

    if header_info.profile != 'HDR1':
        body_data = deobfuscate_body(body_data, header_info.randkey)

    conf2jsonFile(output_file, body_data, header_info.profile)
    logging.info("Configuration dumped successfully into file: %s", output_file.name)

def conf_info(input_file):
    logging.info("Extracting configuration info from file: %s", input_file.name)
    file_data = read_file(input_file)
    header_data, body_data = split_file(file_data)
    header_info = parse_header(header_data)
    print_info(header_info, isBackup=True)

    logging.debug("First 16 bytes of body: %s", body_data[:16])

    if header_info.profile != 'HDR1':
        check_lost_ascii(body_data, header_info.randkey)

    if logging.getLogger().level == logging.DEBUG:
        with open("debug_body_dump.bin", "wb") as debug_file:
            debug_file.write(body_data)
        logging.debug("Body data dumped to debug_body_dump.bin for further analysis")

    try:
        logging.debug("Decoded body (first 16 bytes): %s", body_data[:16].decode('ascii', errors='replace'))
    except Exception as e:
        logging.debug("Failed to decode body: %s", e)

def test_randkeys(file_path):
    with open(file_path, "rb") as f:
        file_data = f.read()
    header_data, body_data = split_file(file_data)
    logging.info("Testing recommended Randkeys: %s", suggest_randkey())
    for key in suggest_randkey():
        try:
            deobfuscated = deobfuscate_body(body_data, key)
            decoded = deobfuscated[:16].decode('ascii', errors='replace')
            logging.info("Randkey=%d: Decoded body: %s", key, decoded)
        except Exception as e:
            logging.warning("Randkey=%d: Failed to decode body: %s", key, e)

def decode_with_randkey(input_file, output_file, randkey):
    logging.info("Decoding file %s with Randkey=%d", input_file.name, randkey)
    file_data = read_file(input_file)
    header_data, body_data = split_file(file_data)
    deobfuscated = deobfuscate_body(body_data, randkey)
    write_file(output_file, deobfuscated)
    logging.info("Decoded file saved to %s", output_file.name)

def parse_cli():
    parser = ArgumentParser(description='** Asuswrt Configs Deobfuscator by BigNerd95 **')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    subparser = parser.add_subparsers(dest='subparser_name', required=True)

    infoParser = subparser.add_parser('info', help='Conf info')
    infoParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))

    dumpParser = subparser.add_parser('dump', help='Conf dump')
    dumpParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    dumpParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('w'))

    packParser = subparser.add_parser('pack', help='Conf pack')
    packParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('r'))
    packParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))
    packParser.add_argument('-p', '--plain', required=False, action='store_true')

    testParser = subparser.add_parser('test', help='Test different Randkeys')
    testParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', help='Input file to test Randkeys')

    decodeParser = subparser.add_parser('decode', help='Decode with specific Randkey')
    decodeParser.add_argument('-i', '--input', required=True, metavar='INPUT_FILE', type=FileType('rb'))
    decodeParser.add_argument('-o', '--output', required=True, metavar='OUTPUT_FILE', type=FileType('wb'))
    decodeParser.add_argument('-r', '--randkey', required=True, metavar='RANDKEY', type=int, help='Randkey to use for decoding')

    args = parser.parse_args()

    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)

    return args

def main():
    args = parse_cli()
    if args.subparser_name == 'info':
        conf_info(args.input)
    elif args.subparser_name == 'dump':
        conf_dump(args.input, args.output)
    elif args.subparser_name == 'pack':
        conf_pack(args.input, args.output, args.plain)
    elif args.subparser_name == 'test':
        test_randkeys(args.input)
    elif args.subparser_name == 'decode':
        decode_with_randkey(args.input, args.output, args.randkey)

if __name__ == '__main__':
    main()
