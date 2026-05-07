# GadgetHunter [![DOI](https://img.shields.io/badge/DOI-10.1145%2F3797065-1f6feb?logo=doi&logoColor=white)](https://doi.org/10.1145/3797065) [![PACMSE FSE 2026](https://img.shields.io/badge/PACMSE-FSE%202026-0a7bbb)](https://doi.org/10.1145/3797065) [![Paper](https://img.shields.io/badge/Paper-PDF-b31b1b?logo=adobeacrobatreader&logoColor=white)](paper/kaixuan-FSE26_GadgetHunter.pdf) [![License: Apache 2.0](https://img.shields.io/badge/License-Apache--2.0-d22128)](LICENSE)

GadgetHunter: Region-Based Neuro-symbolic Detection of Java Deserialization Vulnerabilities

> [!IMPORTANT]
>
> [**2026.05.07**] We are keeping improving the documents and adding more implementation details. 
It will be ready before the FSE 2026 conference. 
Please check back later for the latest updates. :)

## Paper

> Kaixuan Li, Jian Zhang, Chong Wang, Sen Chen, Zong Cao, Min Zhang, Yang Liu.
> **GadgetHunter: Region-Based Neuro-symbolic Detection of Java Deserialization Vulnerabilities.**
> *Proc. ACM Softw. Eng.* 3, FSE, Article FSE003 (July 2026), 22 pages.
> [doi:10.1145/3797065](https://doi.org/10.1145/3797065)

Preprint version is vendored [**here**](paper/kaixuan-FSE26_GadgetHunter.pdf).

<details><summary>BibTeX</summary>

```bibtex
@article{li2026gadgethunter,
  author    = {Li, Kaixuan and Zhang, Jian and Wang, Chong and Chen, Sen and
               Cao, Zong and Zhang, Min and Liu, Yang},
  title     = {{GadgetHunter}: Region-Based Neuro-symbolic Detection of
               {Java} Deserialization Vulnerabilities},
  journal   = {Proc. ACM Softw. Eng.},
  volume    = {3},
  number    = {FSE},
  articleno = {FSE003},
  numpages  = {22},
  year      = {2026},
  month     = jul,
  publisher = {Association for Computing Machinery},
  doi       = {10.1145/3797065}
}
```

</details>

## Overview

GadgetHunter detects Java deserialization gadget chains in three stages:

1. **Stage 1 — Static taint analysis** (Tai-e) over-approximates candidate chains.
2. **Stage 2 — Region-based semantic reachability** partitions each chain at dynamic boundaries (reflection, polymorphic dispatch) and queries an LLM oracle.
3. **Stage 3 — Path feasibility** lifts each surviving chain to ⟨Vars, Flow, Guard, Runtime⟩ constraints and discharges them with Z3.

![GadgetHunter overview](assets/overview.png)

Phase A = Stage 1 (Java). Phase B = Stages 2–3 (Python multi-agent stack).


## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
