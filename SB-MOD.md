### New features of 7-Zip ZS @sebres edition:

- server or interactive mode, parameter `--srv-mode`, can be used as server application, for mass processing, bulk commands or automation purposes (e. g. CI/CD from script langs, etc);
- new cmd-line argument `-ekey...` to direct setting of encryption key (and if needed also IV) in hex form, corresponding 32 or 32+16 bytes (to use it instead of `-p...`); the key and iv used as they provided (without salt, without 2**19-times iterated hashing to derive the key), no salt and no IV (if specified with key) will be stored inside the 7z container in that case, so always the same entire key must be used for decryption ([2acebd0](https://github.com/sebres/7-Zip-zstd/commit/2acebd079abe1035143057945a5c905516235ef0))
  * zstd/brotli: implemented direct AES256-CBC encryption/decryption (with parameter `-ekey$key$iv`) without 7z container;
  * zstd/brotli encrypted stream can be decrypted with standard AES256-CBC with PKCS#7 padding, e. g. using openssl:
   ```
    ke=6061616161616161616161616161616161616161616161616161616161616160; iv=2d69696969696969696969696969692d
    echo -n 'test' | 7z a -tzstd -si -so -ekey$ke$iv . | openssl enc -aes-256-cbc -nosalt -K "$ke" -iv "$iv" -d | zstd -dfc
   ```
- allows partial extraction with new command-line parameter `-eoffs=$offs:$len` for direct access to block with offset/length (currently for types 7z, brotli and zstd only) ([13e6114](https://github.com/sebres/7-Zip-zstd/commit/13e61147c4d75db0d00411aec3a7d9ed23a6719c))
- srv-mode: support different redirects of input and output (`<`, `>`, `1>`, `2>`, `>>`, `1>>`, `2>>`) supplied in a command, e. g. to extract single file from archive with -so parameter ([7d0caaa](https://github.com/sebres/7-Zip-zstd/commit/7d0caaabbd81d4be535d4ae2ecc84a2295e30283), etc);
  support redirects from/to handle (`<&n`, `>&n`, `1>&n`, `2>&n`) ([49869cc](https://github.com/sebres/7-Zip-zstd/commit/49869cc1d633367dced3c672dcd1e501a1f22304));
- srv-mode: also support a stdin redirect with seek to the offset of the archive stream in the file (`<$path?offs=$offs`), for example:
  `e -tzstd -bso2 -so -si -- >/path/to/exracted.txt </path/to/file-with-archive?offs=12345`
  so it makes possible to bypass some header with meta-info etc before the archive content, or to extract data from file containing several archive streams;

