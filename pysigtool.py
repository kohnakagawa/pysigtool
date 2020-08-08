import os
import sys

import lief


def extract_authenticode(exe: str) -> None:
    try:
        binary: lief.PE.Binary = lief.PE.parse(exe)
        if not binary.has_signature:
            print(f"{exe} does not have digital signatures", file=sys.stdout)
            return

        size: int = binary.data_directories[
            lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE
        ].size
        offset: int = binary.data_directories[
            lief.PE.DATA_DIRECTORY.CERTIFICATE_TABLE
        ].rva
        with open(exe, "rb") as fin:
            raw_data = fin.read()
        sign_entry = raw_data[offset : offset + size]

        out_name = os.path.join(
            os.path.abspath(os.path.dirname(exe)),
            os.path.basename(exe).replace(".", "_") + ".der",
        )
        with open(out_name, "wb") as fout:
            fout.write(bytes(sign_entry[8:]))  # skip header
        print(f"saving {out_name}")
    except Exception as e:
        print(e, file=sys.stderr)


def main() -> None:
    if len(sys.argv) < 2:
        print(f"{sys.argv[0]} exe0 exe1 ...", file=sys.stderr)
        return

    for exe in sys.argv[1:]:
        extract_authenticode(exe)


if __name__ == "__main__":
    main()
