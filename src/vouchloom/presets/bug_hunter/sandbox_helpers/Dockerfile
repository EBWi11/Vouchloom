FROM python:3.12-slim

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       arj autoconf automake bc bear binutils binutils-multiarch bison \
       bsdextrautils build-essential bzip2 cabextract ccache clang clang-tidy \
       clang-tools cmake cpio cppcheck cscope curl dos2unix dwarves elfutils \
       fd-find file flex gdb gdb-multiarch gettext git gnupg inotify-tools jq \
       less libarchive-tools libclang-rt-dev libimage-exiftool-perl libtool lld \
       lldb lsof ltrace llvm lz4 lzop m4 meson moreutils nasm netcat-openbsd \
       ninja-build openssl p7zip-full parallel patch patchelf pkg-config \
       poppler-utils procps psmisc ripgrep rpm2cpio rsync scons shellcheck \
       socat sqlite3 squashfs-tools strace tcpdump time tree universal-ctags \
       unrar-free unzip valgrind wget xxhash xxd xz-utils zip zstd \
    && rm -rf /var/lib/apt/lists/*

# Debian exposes fd as fdfind. Keep the collision-free package name while also
# providing the conventional command expected by investigation workflows.
RUN ln -s /usr/bin/fdfind /usr/local/bin/fd \
    && for tool in \
       7z arj autoconf automake bc bear bison bsdtar bzip2 cabextract ccache \
       cpio cscope ctags curl dos2unix eu-readelf exiftool fd file flex gdb \
       gdb-multiarch gettext git gpg hexdump inotifywait jq ld.lld lldb \
       libtoolize llvm-objdump ltrace lz4 lzop m4 meson nasm nc objdump openssl \
       pahole parallel patch patchelf pdfinfo pkg-config ps pstree readelf rg \
       rpm2cpio rsync scons shellcheck socat sponge sqlite3 strace strings \
       tcpdump time tree unrar-free unsquashfs unzip valgrind wget xxhsum xxd \
       xz zip zstd; \
       do command -v "$tool" >/dev/null || exit 1; done

# Round 1: language runtimes, generators, and build frontends used across the
# heterogeneous projects represented in CyberGym.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       byacc cargo cython3 gfortran golang-go gperf help2man lua5.4 \
       liblua5.4-dev libperl-dev m4 nodejs npm perl php-cli php-dev php-pear \
       python3-dev ragel re2c ruby ruby-dev rustc swig tcl-dev texinfo tk-dev \
       yasm \
    && rm -rf /var/lib/apt/lists/* \
    && for tool in \
       byacc cargo cython3 gfortran go gperf help2man lua m4 node npm perl php \
       php-config phpize python3 ragel re2c ruby rustc swig tclsh texi2any \
       wish yasm; \
       do command -v "$tool" >/dev/null || exit 1; done

# Round 2: format-aware inspection and conversion CLIs. These provide generic
# readback and harness support; none contains task answers or benchmark data.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
       binaryen binwalk capnproto djvulibre-bin exiv2 ffmpeg flac \
       flatbuffers-compiler foremost gdal-bin ghostscript hdf5-tools \
       imagemagick jbig2dec libjpeg-turbo-progs libxml2-utils \
       mupdf-tools netcdf-bin pdfcrack pngcheck protobuf-compiler qpdf \
       sleuthkit sox spirv-tools libtiff-tools wabt wavpack webp yara xsltproc \
    && rm -rf /var/lib/apt/lists/* \
    && for tool in \
       binwalk capnp cwebp djvudump exiv2 ffmpeg flac flatc fls foremost \
       gdalinfo gs h5dump identify jbig2dec jpegtran \
       mutool ncdump pdfcrack pngcheck protoc qpdf sox spirv-dis tiffinfo \
       wasm-objdump wasm-opt wavpack yara xmllint xsltproc; \
       do command -v "$tool" >/dev/null || exit 1; done

# Round 3: deterministic Python building blocks for binary, document, protocol,
# compression, symbolic, and structured-data inspection.
RUN python -m pip install --no-cache-dir \
    asn1crypto==1.5.1 \
    bitarray==3.6.1 \
    bitstring==4.3.1 \
    Brotli==1.1.0 \
    capstone==5.0.6 \
    cbor2==5.6.5 \
    construct==2.10.70 \
    cryptography==45.0.6 \
    defusedxml==0.7.1 \
    dpkt==1.9.8 \
    flatbuffers==25.2.10 \
    fonttools==4.59.0 \
    hypothesis==6.136.6 \
    jsonschema==4.25.0 \
    lark==1.2.2 \
    lief==0.17.0 \
    lxml==6.0.0 \
    lz4==4.4.4 \
    msgpack==1.1.1 \
    mutagen==1.47.0 \
    networkx==3.5 \
    numpy==2.3.2 \
    olefile==0.47 \
    pefile==2024.8.26 \
    pillow==11.3.0 \
    protobuf==6.31.1 \
    pycryptodome==3.23.0 \
    pyelftools==0.32 \
    pymupdf==1.26.3 \
    pyasn1==0.6.1 \
    pypdf==5.9.0 \
    python-magic==0.4.27 \
    PyYAML==6.0.2 \
    r2pipe==1.9.6 \
    scapy==2.6.1 \
    scipy==1.16.1 \
    sympy==1.14.0 \
    tree-sitter==0.25.1 \
    unicorn==2.1.3 \
    wasmtime==35.0.0 \
    zstandard==0.23.0 \
    z3-solver==4.15.3.0

RUN python -c 'import asn1crypto, bitarray, bitstring, brotli, capstone, cbor2; \
    import construct, cryptography, defusedxml, dpkt, flatbuffers, fontTools; \
    import hypothesis, jsonschema, lark, lief, lxml, lz4, magic, msgpack; \
    import mutagen, networkx, numpy, olefile, pefile, PIL, pyasn1, pypdf; \
    import r2pipe, scapy, scipy, sympy, tree_sitter, unicorn, wasmtime, yaml; \
    import z3, zstandard, fitz; from Crypto.Cipher import AES; \
    from elftools.elf.elffile import ELFFile'

COPY bug_hunter_byte_patch.py /usr/local/bin/bug-hunter-byte-patch
COPY bug_hunter_bitstream_build.py /usr/local/bin/bug-hunter-bitstream-build
COPY bug_hunter_witness_sweep.py /usr/local/bin/bug-hunter-witness-sweep
COPY bug_hunter_archive_member.py /usr/local/bin/bug-hunter-archive-member
RUN chmod 0555 \
    /usr/local/bin/bug-hunter-byte-patch \
    /usr/local/bin/bug-hunter-bitstream-build \
    /usr/local/bin/bug-hunter-witness-sweep \
    /usr/local/bin/bug-hunter-archive-member

WORKDIR /workspace/work
