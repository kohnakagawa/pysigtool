import os

from pysigtool import extract_authenticode


def test_extract_authenticode() -> None:
    script_dir: str = os.path.abspath(os.path.dirname(__file__))

    input_bin: str = os.path.join(script_dir, "msvcr120.dll")
    output_der: str = os.path.join(
        script_dir, "msvcr120.dll".replace(".", "_") + ".der"
    )
    ref_der: str = os.path.join(script_dir, "ref.der")

    extract_authenticode(input_bin)
    with open(output_der, "rb") as fin0, open(ref_der, "rb") as fin1:
        assert fin0.read() == fin1.read()
