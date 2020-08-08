pysigtool
=======================================
[![Checked with mypy](http://www.mypy-lang.org/static/mypy_badge.svg)](http://mypy-lang.org/)

Extract digital signatures contained in a PE file.

Install
---------------------------------------

```
$ pip install pysigtool
```

Usage
---------------------------------------

```
$ pysigtool msvcr120.dll
saving msvcr120_dll.der
$ ls msvcr120_dll.der
msvcr120_dll.der
$ openssl pkcs7 -in msvcr120_dll.der -inform der -print
PKCS7: 
  type: pkcs7-signedData (1.2.840.113549.1.7.2)
  d.sign: 
    version: 1
    md_algs:
        algorithm: sha1 (1.3.14.3.2.26)
        parameter: NULL
    contents: 
      type: undefined (1.3.6.1.4.1.311.2.1.4)
      d.other: SEQUENCE:
....
```

