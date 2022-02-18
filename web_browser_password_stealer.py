import base64
import os
import platform
import json
import re
import ctypes
import sys

OS = [
    {
        "Windows": {
            "Firefox": {
                "path": "AppData/Roaming/Mozilla/Firefox",
                "dll": "nss3.dll",
                "locations": [
                    "",
                    os.path.expanduser("~\\AppData\\Local\\Mozilla Firefox"),
                    os.path.expanduser("~\\AppData\\Local\\Mozilla Thunderbird"),
                    os.path.expanduser("~\\AppData\\Local\\Nightly"),
                    os.path.expanduser("~\\AppData\\Local\\SeaMonkey"),
                    os.path.expanduser("~\\AppData\\Local\\Waterfox"),
                    "C:\\Program Files\\Mozilla Firefox",
                    "C:\\Program Files\\Mozilla Thunderbird",
                    "C:\\Program Files\\Nightly",
                    "C:\\Program Files\\SeaMonkey",
                    "C:\\Program Files\\Waterfox",
                ],
            },
        }
    },
    {
        "Linux": {
            "Firefox": {
                "path": ".mozilla/firefox",
                "dll": "libnss3.so",
                "locations": [
                    "",
                    "/usr/lib64",
                    "/usr/lib64/nss",
                    "/usr/lib",
                    "/usr/lib/nss",
                    "/usr/local/lib",
                    "/usr/local/lib/nss",
                    "/opt/local/lib",
                    "/opt/local/lib/nss",
                    os.path.expanduser("~/.nix-profile/lib"),
                ],
            },
        }
    },
    {
        "Mac": {
            "Firefox": {
                "path": "Library/Application Support/Firefox",
                "dll": "libnss3.dylib",
                "locations": [
                    "",
                    "/usr/local/lib/nss",
                    "/usr/local/lib",
                    "/opt/local/lib/nss",
                    "/sw/lib/firefox",
                    "/sw/lib/mozilla",
                    "/usr/local/opt/nss/lib",
                    "/opt/pkg/lib/nss",
                    "/Applications/Firefox.app/Contents/MacOS",
                    "/Applications/Thunderbird.app/Contents/MacOS",
                    "/Applications/SeaMonkey.app/Contents/MacOS",
                    "/Applications/Waterfox.app/Contents/MacOS",
                ],
            }
        }
    },
]


class SECItem(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_uint),
        ("data", ctypes.c_char_p),
        ("len", ctypes.c_uint),
    ]


def get_basepath():
    os_name = platform.system()
    for system in OS:
        try:
            basepath = os.path.join(
                os.path.expanduser("~"), system[os_name]["Firefox"]["path"]
            )
            return basepath, system[os_name]
        except:
            pass
    sys.exit("Your OS is not supported!")


def initialization(os_name):
    for location in os_name["Firefox"]["locations"]:
        nsslib_path = os.path.join(location, os_name["Firefox"]["dll"])
        try:
            nsslib = ctypes.CDLL(nsslib_path)
        except:
            pass
        else:
            return nsslib
    sys.exit("NSS dll is not found!")


def get_profiles(basepath):
    profiles_path = os.path.join(basepath, "profiles.ini")
    with open(profiles_path, "r") as f:
        data = f.read()

    profiles = [
        os.path.join(basepath, p.strip()[5:])
        for p in re.findall(r"^Path=.+(?s:.)$", data, re.M)
    ]
    return profiles


def decrypt_profiles(nsslib, profiles):
    decrypted_profiles = []

    for profile in profiles:
        logins = os.path.join(profile, "logins.json")
        if os.path.isfile(logins):

            if nsslib.NSS_Init(profile.encode("utf8")) == 0:
                with open(logins, "r") as f:
                    data = json.load(f)

                decrypted_profiles.append(
                    {
                        profile: [
                            {
                                "Hostname": d["hostname"],
                                "Username": decrypt_data(
                                    nsslib, d["encryptedUsername"]
                                ),
                                "Password": decrypt_data(
                                    nsslib, d["encryptedPassword"]
                                ),
                            }
                            for d in data["logins"]
                        ]
                    }
                )
            else:
                sys.exit("NSS initialization failed!")
    return decrypted_profiles


def decrypt_data(nsslib, encrypted_data):
    data = base64.b64decode(encrypted_data)
    cipher_text = SECItem(0, data, len(data))
    plain_text = SECItem(0, None, 0)
    if (
        nsslib.PK11SDR_Decrypt(
            ctypes.byref(cipher_text), ctypes.byref(plain_text), None
        )
        != 0
    ):
        print("[X] PK11SDR_Decrypt failed!")

    return ctypes.string_at(plain_text.data, plain_text.len).decode("utf8")


def display_plain_data(decrypted_profiles, nsslib):
    for profile in decrypted_profiles:
        for key, value in profile.items():
            print(
                str(" Profile " + key.split("/")[-1] + " ").center(
                    os.get_terminal_size().columns, "#"
                )
                + "\n"
            )
            [
                print(
                    "Hostname: "
                    + v["Hostname"]
                    + "\nUsername: "
                    + v["Username"]
                    + "\nPassword: "
                    + v["Password"]
                    + "\n"
                )
                for v in value
            ]

    if nsslib.NSS_Shutdown() != 0:
        sys.exit("NSS shutdown failed!")


if __name__ == "__main__":
    basepath, system = get_basepath()
    nsslib = initialization(system)
    profiles = get_profiles(basepath)
    decrypted_profiles = decrypt_profiles(nsslib, profiles)
    display_plain_data(decrypted_profiles, nsslib)