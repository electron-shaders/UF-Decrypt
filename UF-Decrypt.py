import os
import re
import zlib
import gzip
import json
import tkinter as tk
from tkinter import filedialog
from getch import pause_exit

xor_table = [0x13, 0x5B, 0xC, 0xD, 0x66, 0x16, 0x22, 0x2B, 0x11, 0x19, 0x58, 0x40, 0x24, 0x10, 0xE, 0x42, 0x31, 0x57, 0x38, 0x2C, 0x35, 0x1C, 0xB, 5, 0x74, 0x25, 0x3A, 0x69, 0x14, 0xF, 0x4D, 7, 0x1D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13, 0x5B, 0xC, 0xD, 0x66, 0x16, 0x22, 0x2B, 0x11, 0x19, 0x58, 0x40, 0x24, 0x10, 0xE, 0x42, 0x31, 0x57, 0x38, 0x2C, 0x35, 0x1C, 0xB, 5, 0x74, 0x25, 0x3A, 0x69, 0x14, 0xF, 0x4D, 7, 0x1D, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
encrypted_ccz_files = list()
pvr_files = list()
orig_files = list()
dec_files = list()

def join_and_replace(base, file):
    path = os.path.join(base, file)
    return re.sub('\\\\', '/', path)

def decryptUF(_pInBuff, _pInSize):
    if _pInSize <= 3:
        return -1

    if _pInBuff[0] != 85 or _pInBuff[1] != 70:
        return -2

    if _pInBuff[2] == 79:
        v5 = 4
        # *a4 = (unsigned __int8)_pInBuff[3];
        v8 = 1
        v6 = 5
        v7 = 6
        v9 = 4
    else:
        v5 = 2
        v6 = 3
        v7 = 4
        v8 = 0
        v9 = 2

    # *a3 = (unsigned __int8)_pInBuff[v5]
    v10 = _pInBuff[v6]

    if v10 == 1:
        _pOutSize = _pInSize - 3 - v9
        if _pOutSize <= 0:
            return _pOutSize
        v15 = v9 + 3
        v16 = _pInBuff
        v16i = 0
        v17 = _pOutSize + v9 + 3
        v18 = _pInBuff[v7] - v9 - 3
        while True:
            v19 = v18 + v15
            v20 = _pInBuff[v15]
            v15 += 1
            v16[v16i] = xor_table[v19 % 33] ^ v20
            v16i += 1
            if v15 == v17:
                break
        return _pOutSize

    else:
        if v10 != 2:
            v11 = 0
            if v8:
                v12 = 7
            else:
                v12 = 5
            _pOutSize = _pInSize - v12
            if _pOutSize > 0:
                while True:
                    _pInBuff[v11] = _pInBuff[v12 + v11]
                    v11 += 1
                    if _pOutSize <= v11:
                        break
            return _pOutSize

        v21 = _pInBuff[v7]
        v22 = v9 + 3
        _pOutSize = _pInSize - v22
        _pInBuff[0] = _pInBuff[_pOutSize] ^ xor_table[v21 % 0x21 + 48]
        _pInBuff[1] = _pInBuff[_pOutSize + 1] ^ xor_table[v21 + 1 - 33 * (((1041204193 * (v21 + 1)) >> 32) >> 3) + 48]
        _pInBuff[2] = _pInBuff[_pOutSize + 2] ^ xor_table[v21 + 2 - 33 * (((1041204193 * (v21 + 2)) >> 32) >> 3) + 48]
        _pInBuff[3] = _pInBuff[_pOutSize + 3] ^ xor_table[v21 + 3 - 33 * (((1041204193 * (v21 + 3)) >> 32) >> 3) + 48]
        _pInBuff[4] = _pInBuff[_pOutSize + 4] ^ xor_table[v21 + 4 - 33 * (((1041204193 * (v21 + 4)) >> 32) >> 3) + 48]
        if v9 != 2:
            _pInBuff[5] = _pInBuff[_pOutSize + 5] ^ xor_table[v21 + 5 - 33 * (((1041204193 * (v21 + 5)) >> 32) >> 3) + 48]
            _pInBuff[6] = _pInBuff[_pOutSize + 6] ^ xor_table[v21 + 6 - 33 * (((1041204193 * (v21 + 6)) >> 32) >> 3) + 48]

        if _pOutSize - v22 > 95:
            v23 = 95
        else:
            v23 = _pOutSize - v22

        v24 = v23 + v22
        if v22 >= v24:
            return _pOutSize

        v25 = v21 + v22
        v26 = v22
        v27 = v21 + v24
        while True:
            v28 = v25 % 33
            v25 += 1
            _pInBuff[v26] ^= xor_table[v28 + 48]
            v26 += 1
            if v25 == v27:
                break
        return _pOutSize

def isCCZBuffer(_pInBuff, _pInSize):
    return _pInSize >= 0xF and _pInBuff[0] == 67 and _pInBuff[1] == 67 and _pInBuff[2] == 90 and (_pInBuff[3] == 112 or _pInBuff[3] == 33)

def isGZipBuffer(_pInBuff, _pInSize):
    return _pInSize > 1 and _pInBuff[0] == 0x1F and _pInBuff[1] == 0x8B

def CCZBuffer2PNG(_pInBuff):
    if _pInBuff[3] == 112:
        # TODO: decrypt CCZ
        print("\r[INFO] Detected PVR.CCZ archive. Inflating ==> %s ... FAILED" % os.path.basename(fout_path))
        print("[WIP] Current CCZ archive is encrypted. Ignored: %s\n" % os.path.basename(fin_path))
        encrypted_ccz_files.append(fin_path)
        return -1

    # CCZ->PVR
    ftmp_path = fin_path + ".pvr"
    with open(ftmp_path, 'wb') as f:
        f.write(zlib.decompress(_pInBuff[16:len(_pInBuff)]))
        f.close()
    
    # PVR->PNG
    print()
    os.system('%s -ics sRGB -i "%s" -d "%s"' % (pvr_cli_path, ftmp_path, fout_path))
    os.remove(ftmp_path)

    if not os.path.exists(fout_path):
        print("\r[INFO] Detected PVR.CCZ archive. Inflating ==> %s ... FAILED" % os.path.basename(fout_path))
        pause_exit(message=
'''
[ERROR] Conversion of PVR->PNG failed:
\tFile path: %s
\tPVRTexToolCLI.exe path: %s
Please check if these paths are valid. (accessible, without space, etc.)
The output from PVRTexToolCLI.exe above might be useful.

Press any key to exit......
'''
        % (fin_path, pvr_cli_path))

    return os.path.getsize(fout_path)

def inflateGZipFile(_pInPath, _pOutPath):
    with open(_pOutPath, 'wb') as f:
        gf = gzip.open(_pInPath, 'rb')
        f.write(gf.read())
        f.close()
        gf.close()

work_path = os.getcwd()
pvr_cli_path = ""
flag = {}
if not os.path.exists(join_and_replace(work_path, "config.json")):
    pause_exit(message="Failed to locate config.json, press any key to exit......")
with open(join_and_replace(work_path, "config.json"), 'r', encoding='utf-8') as f:
    json_body = json.load(f)

    if json_body.get("PvrCliPath") == None:
        pause_exit(message="config.json is invalid, press any key to exit......")
    pvr_cli_path = json_body["PvrCliPath"]

    if json_body.get("flag") == None:
        pause_exit(message="config.json is invalid, press any key to exit......")

    if json_body["flag"].get("isEnabledDeleteOrigFile") == None:
        pause_exit(message="config.json is invalid, press any key to exit......")
    flag["isEnabledDeleteOrigFile"] = json_body["flag"]["isEnabledDeleteOrigFile"]

    if json_body["flag"].get("isEnabledDeletePVRFile") == None:
        pause_exit(message="config.json is invalid, press any key to exit......")
    flag["isEnabledDeletePVRFile"] = json_body["flag"]["isEnabledDeletePVRFile"]

    if json_body["flag"].get("isEnabledRenameDecFile") == None or not json_body["flag"]["isEnabledDeleteOrigFile"] and json_body["flag"]["isEnabledRenameDecFile"]:
        pause_exit(message="config.json is invalid, press any key to exit......")
    flag["isEnabledRenameDecFile"] = json_body["flag"]["isEnabledRenameDecFile"]
    del json_body
root = tk.Tk()
root.withdraw()

work_path = filedialog.askdirectory(title="Please select the folder to decrypt", initialdir=work_path)
if not work_path:
    pause_exit(message="No folder is selected, press any key to exit......")
del root, filedialog, tk

for root, dirs, files in os.walk(work_path):
    for file in files:
        fin_path = join_and_replace(root, file)
        fout_path = os.path.splitext(fin_path)[0] + "_dec" + os.path.splitext(fin_path)[1]

        with open(fin_path, 'rb') as f:
            print("\r[INFO] Reading: %s ..." % file, end="")
            size = os.path.getsize(fin_path)
            buffer = bytearray(f.read())
            f.close()
            print("\r[INFO] Reading: %s ... ok" % file)

        print("\r[INFO] Decrypting: %s ..." % file, end="")
        temp = decryptUF(buffer, size)
        print("\r[INFO] Decrypting: %s ... ok" % file)
        if temp < 0:
            print("[INFO] Not an encrypted file. Skipping: %s\n" % file)
            continue
        size = temp
        del temp

        if isCCZBuffer(buffer, size):
            print("\r[INFO] Detected PVR.CCZ archive. Inflating ==> %s ..." % os.path.basename(fout_path), end="")
            size = CCZBuffer2PNG(buffer)
            if size != -1:
                print("\r[INFO] Detected PVR.CCZ archive. Inflating ==> %s ... ok\n" % os.path.basename(fout_path))
                if flag["isEnabledDeleteOrigFile"]:
                    orig_files.append(fin_path)
                if flag["isEnabledDeletePVRFile"]:
                    pvr_files.append(fin_path + "_Out.pvr")
                if flag["isEnabledRenameDecFile"]:
                    dec_files.append(fout_path)
            continue

        if isGZipBuffer(buffer, size):
            ftmp_path = fin_path + ".gz"
            print("\r[INFO] Detected GZip archive. Creating temp file ==> %s ..." % os.path.basename(ftmp_path), end="")
            with open(ftmp_path, 'wb') as f:
                f.write(buffer)
                f.close()
            print("\r[INFO] Detected GZip archive. Creating temp file ==> %s ... ok\n" % os.path.basename(ftmp_path))
            print("\r[INFO] Detected GZip archive. Inflating ==> %s ..." % os.path.basename(fout_path), end="")
            inflateGZipFile(ftmp_path, fout_path)
            print("\r[INFO] Detected GZip archive. Inflating ==> %s ... ok\n" % os.path.basename(fout_path))
            if flag["isEnabledDeleteOrigFile"]:
                orig_files.append(fin_path)
            if flag["isEnabledRenameDecFile"]:
                dec_files.append(fout_path)
            continue

        with open(fout_path, 'wb') as f:
            print("\r[INFO] Saving ==> %s ..." % os.path.basename(fout_path), end="")
            f.write(buffer)
            f.close()
            print("\r[INFO] Saving ==> %s ... ok\n" % os.path.basename(fout_path))
            if flag["isEnabledDeleteOrigFile"]:
                orig_files.append(fin_path)
            if flag["isEnabledRenameDecFile"]:
                dec_files.append(fout_path)

if flag["isEnabledDeletePVRFile"] and len(pvr_files):
    for i in range(len(pvr_files)):
        print("\r[INFO] Deleting PVR files...... (%d / %d)" % (i + 1, len(pvr_files)), end="")
        os.remove(pvr_files[i])
    print(" Done!\n")
    del pvr_files

if flag["isEnabledDeleteOrigFile"] and len(orig_files):
    for i in range(len(orig_files)):
        print("\r[INFO] Deleting original files...... (%d / %d)" % (i + 1, len(orig_files)), end="")
        os.remove(orig_files[i])
    print(" Done!\n")
    del orig_files

if flag["isEnabledRenameDecFile"] and len(dec_files):
    for i in range(len(dec_files)):
        print("\r[INFO] Renaming decrypted files...... (%d / %d)" % (i + 1, len(dec_files)), end="")
        matched_groups = re.match(r"^(.*?)(_dec)(\..+)$", dec_files[i]).groups()
        os.rename(dec_files[i], matched_groups[0] + matched_groups[2])
    print(" Done!\n")
    del dec_files, matched_groups

if len(encrypted_ccz_files):
    print("[WIP] The encrypted CCZ files are ignored:")
    for path in encrypted_ccz_files:
        print("\t%s" % path)

pause_exit(message="All Done! Press any key to exit......")