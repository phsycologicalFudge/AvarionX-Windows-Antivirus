<p align="center">
  <img src="assets/icons/logo.png" width="92" alt="AvarionX Security logo">
</p>

<div align="center">

# AvarionX Antivirus 

### A free Windows malware scanner without ads, and tracking.


[![Release](https://img.shields.io/github/v/release/phsycologicalFudge/AvarionX-Windows-Antivirus?logo=github&label=release&color=6366f1)](https://github.com/phsycologicalFudge/AvarionX-Windows-Antivirus/releases)
[![Downloads](https://img.shields.io/github/downloads/phsycologicalFudge/AvarionX-Windows-Antivirus/total?logo=github&label=downloads&color=10b981)](https://github.com/phsycologicalFudge/AvarionX-Windows-Antivirus/releases)
[![License](https://img.shields.io/github/license/phsycologicalFudge/AvarionX-Windows-Antivirus?label=license&color=64748b)](LICENSE)
[![VX-TITANIUM](https://img.shields.io/badge/VX--TITANIUM-XSeries-7c3aed?labelColor=020617)](https://github.com/phsycologicalFudge/AvarionX-Windows-Antivirus)

<a href="https://buymeacoffee.com/ryanfromcolourswift">
  <img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" height="48" alt="Buy me a coffee">
</a>

</div>

## What is AvarionX?

AvarionX Antivirus is a WIP Windows port of the Android antivirus built around user privacy.

## Protection layers

| Layer | What it does |
|---|---|
| **VX-TITANIUM** | Local malware scanning engine for files and APKs. |
| **VTTI Cloud** | Also known as Titanium Cloud. A proprietary cloud Intelligence Platform, including hash checking for AvarionX, and sample analysis for full files |
| **Real-Time Protection** | Monitors new downloads and recent process'. |


## The Engine's Architecture

AvarionX Antivirus (CS Security) operates through a multi-layered detection pipeline powered by VX-Titanium.

1. Cloud Hash Layer: A fast check on an extremely large historical and current corpus of over 200 million unique malware hashes
2. Hash Layer: Comparing both SHA256 and MD5 fingerprints against known malware lists
3. Signature Layer: Custom byte signitures and yara rules.
4. Heuristic Layer: Machine learning based behaviour analysis for APK and PE files

### Machine Learning (ML+)

AvarionX Security includes a dual ML system named ML+. The Windows version is not yet available, but the engine retains its Android ML models.

* Legacy MUniverse Tag: Suspicious applications that meet the scoring system's requirements are dubbed with a MUniverse (Malware Universe) tag.
* Current versions use an upgraded heuristics model, with the tag: Win/VXgen2

### Third Party Attributions

This project includes code derived from [exav](https://github.com/sylvinus/exav/tree/main/crates) by Sylvain Zimmer, under the MIT License. The version included for AvarionX has been substantially modified and is independently maintained as part of this project, under the terms of the MIT licence below:

```
MIT License

Copyright (c) 2026 Sylvain Zimmer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

