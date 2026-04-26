# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for Cybersecurity Companion
#
# Bundling strategy:
#   - Pure-Python / Cython packages: bundled via hiddenimports
#   - Binary/data-heavy packages: use collect_all() to pull all files
#   - torch / sentence_transformers / transformers: EXCLUDED — DLL init
#     fails in PyInstaller temp dirs on Windows. The app falls back
#     gracefully to keyword-search mode via try/except Exception in
#     assistant/rag_assistant.py.

import sys
from PyInstaller.utils.hooks import collect_all, collect_data_files

block_cipher = None

# ─────────────────────────────────────────────────────────────────
#  Bundled data files (read-only assets shipped with the exe)
# ─────────────────────────────────────────────────────────────────
datas    = [
    ('data',   'data'),
    ('assets', 'assets'),
]
binaries      = []
hiddenimports = []

# ── PyQt6 core ───────────────────────────────────────────────────────────────
# collect_all bundles Qt platform DLLs, plugins (qwindows.dll, etc.),
# translations, and Qt6*.dll runtime libraries needed on any Windows machine.
for _pkg in ('PyQt6', 'PyQt6.Qt6', 'PyQt6.sip',
             'PyQt6.QtCore', 'PyQt6.QtGui', 'PyQt6.QtWidgets',
             'PyQt6.QtNetwork', 'PyQt6.QtPrintSupport',
             'PyQt6.QtSvg', 'PyQt6.QtOpenGL'):
    try:
        tmp = collect_all(_pkg)
        datas         += tmp[0]
        binaries      += tmp[1]
        hiddenimports += tmp[2]
    except Exception:
        pass

# ── PyQt6-WebEngine (SEPARATE pip package — must be collected explicitly) ────
# Provides: QtWebEngineCore, QtWebEngineWidgets, QtWebEngineQuick
# browser_tab.py       -> import PyQt6.QtWebEngineCore / QtWebEngineWidgets
# security_settings.py -> from PyQt6.QtWebEngineCore import ...
# download_protection.py -> from PyQt6.QtWebEngineCore import QWebEngineDownloadRequest
for _pkg in ('PyQt6.QtWebEngineCore', 'PyQt6.QtWebEngineWidgets',
             'PyQt6.QtWebEngineQuick'):
    try:
        tmp = collect_all(_pkg)
        datas         += tmp[0]
        binaries      += tmp[1]
        hiddenimports += tmp[2]
    except Exception:
        pass

# Explicit declaration of every PyQt6 module the app imports
hiddenimports += [
    'PyQt6',
    'PyQt6.sip',
    'PyQt6.QtCore',
    'PyQt6.QtGui',
    'PyQt6.QtWidgets',
    'PyQt6.QtNetwork',
    'PyQt6.QtPrintSupport',
    'PyQt6.QtSvg',
    'PyQt6.QtOpenGL',
    # WebEngine — used in browser_tab, security_settings, download_protection
    'PyQt6.QtWebEngineCore',
    'PyQt6.QtWebEngineWidgets',
    'PyQt6.QtWebEngineQuick',
]


# ── joblib ────────────────────────────────────────────────────────
tmp = collect_all('joblib')
datas         += tmp[0]
binaries      += tmp[1]
hiddenimports += tmp[2]

# ── tldextract (browser/security_analyzer.py) ────────────────────
# Bundles the TLD definition files that tldextract downloads at runtime
tmp = collect_all('tldextract')
datas         += tmp[0]
binaries      += tmp[1]
hiddenimports += tmp[2]
datas         += collect_data_files('tldextract')

# ── beautifulsoup4 / bs4 (browser/security_analyzer, privacy_detector) ──
hiddenimports += [
    'bs4',
    'bs4.builder',
    'bs4.builder._htmlparser',
    'bs4.builder._lxml',
    'bs4.element',
    'bs4.formatter',
]

# ── requests (browser/tools.py) ──────────────────────────────────
hiddenimports += [
    'requests',
    'requests.adapters',
    'requests.auth',
    'requests.cookies',
    'requests.exceptions',
    'requests.models',
    'requests.sessions',
    'urllib3',
    'urllib3.util',
    'certifi',
    'charset_normalizer',
    'idna',
]

# ── whois (browser/tools.py — optional, wrapped in try/except) ───
hiddenimports += [
    'whois',
    'whois.parser',
    'whois.query',
]

# ── dnspython (browser/tools.py — optional, wrapped in try/except) ──
hiddenimports += [
    'dns',
    'dns.resolver',
    'dns.rdatatype',
    'dns.rdataclass',
    'dns.message',
    'dns.name',
    'dns.query',
    'dns.exception',
]

# ── markdown (browser_tab.py chat renderer) ──────────────────────
hiddenimports += [
    'markdown',
    'markdown.extensions',
    'markdown.extensions.fenced_code',
    'markdown.extensions.tables',
    'markdown.extensions.codehilite',
    'markdown.extensions.toc',
    'markdown.extensions.attr_list',
    'markdown.extensions.extra',
    'markdown.treeprocessors',
    'markdown.preprocessors',
    'markdown.postprocessors',
    'markdown.blockprocessors',
    'markdown.inlinepatterns',
    'markdown.htmlparser',
    'markdown.serializers',
    'markdown.util',
]

# ── scikit-learn Cython extensions ───────────────────────────────
hiddenimports += [
    'sklearn',
    'sklearn.utils._typedefs',
    'sklearn.utils._heap',
    'sklearn.utils._sorting',
    'sklearn.utils._vector_sentinel',
    'sklearn.neighbors._partition_nodes',
    'sklearn.tree._utils',
    'sklearn.tree._criterion',
    'sklearn.tree._splitter',
    'sklearn.ensemble._forest',
    'sklearn.ensemble._gb_losses',
    'sklearn.feature_extraction.text',
    'sklearn.feature_extraction._stop_words',
]

# ── scipy (auditor/model_auditor.py KS test) ─────────────────────
hiddenimports += [
    'scipy',
    'scipy.stats',
    'scipy.stats._stats_py',
    'scipy.stats._continuous_distns',
    'scipy.stats._distn_infrastructure',
    'scipy.spatial',
    'scipy.spatial.distance',
    'scipy.sparse',
    'scipy.sparse.csr',
    'scipy._lib',
    'scipy.special',
    'scipy.special._ufuncs',
]

# ── numpy ─────────────────────────────────────────────────────────
hiddenimports += [
    'numpy',
    'numpy.core',
    'numpy.core._multiarray_umath',
    'numpy.random',
    'numpy.linalg',
]

# ── stdlib / misc ─────────────────────────────────────────────────
hiddenimports += [
    'sqlite3',
    'logging',
    'pathlib',
    'json',
    're',
    'ssl',
    'socket',
    'hashlib',
    'base64',
    'secrets',
    'string',
    'html',
    'email',
    'urllib',
    'urllib.parse',
    'psutil',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'PIL.ImageFont',
    'PIL.ImageFilter',
    'pandas',
]

# ─────────────────────────────────────────────────────────────────
#  EXCLUDES — heavy packages that must NOT be bundled
# ─────────────────────────────────────────────────────────────────
EXCLUDES = [
    # PyTorch stack — DLL resolution fails in PyInstaller temp dirs.
    # rag_assistant.py catches the OSError and falls back to keyword search.
    'torch',
    'torchvision',
    'torchaudio',
    'sentence_transformers',
    'transformers',
    'tokenizers',
    'huggingface_hub',
    'safetensors',
    'faiss',
    'faiss_cpu',
    # Dev / docs tooling not needed at runtime
    'matplotlib',
    'IPython',
    'jupyter',
    'notebook',
    'pytest',
    'setuptools',
    'pkg_resources',
    'docutils',
    'sphinx',
    'black',
    'pylint',
    'mypy',
]

# ─────────────────────────────────────────────────────────────────
#  ANALYSIS
# ─────────────────────────────────────────────────────────────────
a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='CybersecurityCompanion',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='assets/icon.ico',
)
