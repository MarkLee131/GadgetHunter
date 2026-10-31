# Third-party notices

The source code in this repository (`multi-agents/`, `gleipner_results/scripts/`, and the
configuration files) is licensed under the Apache License 2.0, as stated in [`LICENSE`](LICENSE).

`multi-agents/flash/flash.jar` is different. It is a self-contained ("fat") Java archive that
bundles third-party components, several of which are copyleft-licensed. **The Apache License 2.0 in
`LICENSE` does not apply to, and does not relicense, anything inside that jar.** Each bundled
component remains under its own license.

`backend/strings/src/pascal/taie/util/Strings.java` is also an exception to the repository's Apache license. It is a modified Flash/Tai-e helper under **LGPL-3.0-or-later**, with its original copyright and license header retained. Its complete source, upstream revision, changes and build procedure are included in [`backend/strings/`](backend/strings/README.md). Generated per-scan `backend-overlay.jar` files contain that helper; the bundled `flash.jar` remains unchanged.

The Java sources in [`backend/fair/`](backend/fair/README.md) are also **LGPL-3.0-or-later**. This optional collector adapter changes traversal scheduling and reports internal search budgets while delegating checks and emission to the bundled collector. Its full source and build procedure are included. When selected, its classes and analysis registry are added to the per-scan overlay; they do not modify the bundled JAR.

## What the jar is, and what we changed

The jar is a modified build of **Flash** (Yiheng Zhang, Ming Wen, Shunjie Liu, Dongjie He, and Hai
Jin. *Precise and Effective Gadget Chain Mining through Deserialization Guided Call Graph
Construction.* 34th USENIX Security Symposium, 2025), whose analysis backend is **Tai-e** (Tian Tan
and Yue Li. *Tai-e: A developer-friendly static analysis framework for Java by harnessing the good
designs of classics.* ISSTA 2023). Its entry point is `pascal.taie.Main`.

Our modification was made in **August 2025** and is confined to how candidate gadget chains are
emitted. As described in §4 of the accompanying paper, we changed Flash so that every edge of an
emitted chain additionally carries the JVM-level information the LLM stage consumes: the call
instruction kind (`STATIC`, `SPECIAL`, `VIRTUAL`, `INTERFACE`, `DYNAMIC`), the call-site line number,
and the taint annotations for the receiver and parameters. We did not modify the analysis algorithms
of Tai-e or Soot.

## Copyleft components

These bundled components are copyleft-licensed and impose obligations on anyone who redistributes
the jar. The license identifications below are the licenses declared by each upstream project; the
authoritative text is the one published by that project.

| Component | Coordinates | License | Upstream |
| --- | --- | --- | --- |
| Tai-e | `pascal.taie` (the jar's primary artifact) | LGPL-3.0 | <https://github.com/pascal-lab/Tai-e> |
| Soot | `org.soot-oss:soot:4.4.1` | LGPL-2.1 | <https://github.com/soot-oss/soot> |
| Heros | `de.upb.cs.swt:heros:1.2.3` | LGPL-2.1 | <https://github.com/Sable/heros> |
| Jasmin | `ca.mcgill.sable:jasmin:3.0.3` | LGPL-2.1 | <https://github.com/Sable/jasmin> |
| Polyglot | `polyglot.*` (bundled by Soot) | LGPL-2.1 | <https://www.cs.cornell.edu/projects/polyglot/> |

The full text of each license above is in [`licenses/`](licenses/):

| File | License |
| --- | --- |
| [`licenses/LGPL-3.0.txt`](licenses/LGPL-3.0.txt) | GNU Lesser General Public License v3.0 (applies to Tai-e) |
| [`licenses/GPL-3.0.txt`](licenses/GPL-3.0.txt) | GNU General Public License v3.0, which LGPL-3.0 incorporates by reference |
| [`licenses/LGPL-2.1.txt`](licenses/LGPL-2.1.txt) | GNU Lesser General Public License v2.1 (applies to Soot, Heros, Jasmin, Polyglot) |

`licenses/LGPL-3.0.txt` and `licenses/GPL-3.0.txt` are byte-for-byte the `COPYING.LESSER` and
`COPYING` entries carried inside the jar; verify with:

```bash
unzip -p multi-agents/flash/flash.jar COPYING        | diff - licenses/GPL-3.0.txt
unzip -p multi-agents/flash/flash.jar COPYING.LESSER | diff - licenses/LGPL-3.0.txt
```

The jar also carries the notices of two other bundled projects:

```bash
unzip -p multi-agents/flash/flash.jar META-INF/LICENSE      # Apache License 2.0 (Apache Log4j)
unzip -p multi-agents/flash/flash.jar META-INF/NOTICE       # Apache Log4j attribution
unzip -p multi-agents/flash/flash.jar META-INF/LICENSE.txt  # MIT License (QOS.ch, SLF4J)
unzip -p multi-agents/flash/flash.jar META-INF/NOTICE.txt
```

Note that `META-INF/DEPENDENCIES` inside the jar is a file shipped by Apache Log4j and describes
Log4j's own optional dependencies. It is **not** an inventory of what this jar bundles; the
inventory below is.

## Complete bundled inventory

Every component below was read from the jar's own `META-INF/maven/*/pom.properties` entries, so the
coordinates and versions are exact. Reproduce this list with:

```bash
for f in $(unzip -l multi-agents/flash/flash.jar | awk '{print $4}' \
             | grep 'META-INF/maven/.*/pom.properties'); do
  unzip -p multi-agents/flash/flash.jar "$f" | grep -E '^(groupId|artifactId|version)='
done
```

```
ca.mcgill.sable:jasmin:3.0.3
com.fasterxml.jackson.core:jackson-annotations:2.15.0
com.fasterxml.jackson.core:jackson-core:2.15.0
com.fasterxml.jackson.core:jackson-databind:2.15.0
com.fasterxml.jackson.dataformat:jackson-dataformat-yaml:2.15.0
com.google.code.findbugs:jsr305:3.0.2
com.google.code.gson:gson:2.8.9
com.google.errorprone:error_prone_annotations:2.11.0
com.google.guava:failureaccess:1.0.1
com.google.guava:guava:31.1-android
com.google.guava:listenablefuture:9999.0-empty-to-avoid-conflict-with-guava
com.google.j2objc:j2objc-annotations:1.3
com.google.protobuf:protobuf-java:3.21.7
com.google.protobuf:protobuf-java-util:3.21.2
com.opencsv:opencsv:5.5.1
com.sun.istack:istack-commons-runtime:3.0.7
com.sun.xml.fastinfoset:FastInfoset:1.2.15
commons-beanutils:commons-beanutils:1.9.4
commons-collections:commons-collections:3.2.2
commons-io:commons-io:2.7
commons-logging:commons-logging:1.2
de.upb.cs.swt:axml:2.1.3
de.upb.cs.swt:heros:1.2.3
javax.activation:javax.activation-api:1.2.0
javax.annotation:javax.annotation-api:1.3.2
javax.xml.bind:jaxb-api:2.4.0-b180830.0359
org.apache.commons:commons-collections4:4.4
org.apache.commons:commons-lang3:3.12.0
org.apache.commons:commons-text:1.9
org.apache.logging.log4j:log4j-api:2.20.0
org.apache.logging.log4j:log4j-core:2.20.0
org.glassfish.jaxb:jaxb-runtime:2.4.0-b180830.0438
org.glassfish.jaxb:txw2:2.4.0-b180830.0438
org.jvnet.staxex:stax-ex:1.8
org.slf4j:slf4j-api:2.0.7
org.slf4j:slf4j-nop:2.0.7
org.soot-oss:soot:4.4.1
org.yaml:snakeyaml:2.0
```

Soot additionally bundles code that has no Maven descriptor of its own and therefore does not appear
above. Those packages are visible in the jar's directory listing and include `polyglot.*`, `ppg.*`,
`java_cup.*`, `jasmin.*`, `jas.*`, `beaver.*`, `fj.*` (Functional Java), `scm.*`, `org.jf.*`
(smali / dexlib2), `pxb.android.*`, and `ch.randelshofer.*`. List them with:

```bash
unzip -l multi-agents/flash/flash.jar | awk '{print $4}' | grep '\.class$' \
  | awk -F/ '{print $1}' | sort -u
```

## Written offer for corresponding source

The LGPL requires that recipients be able to obtain the source of the covered library, including any
modifications to it. The unmodified upstream sources are published at the URLs in the table above.

For the components covered by the LGPL that are distributed in object form inside
`multi-agents/flash/flash.jar`, **and for our modification to Flash's chain emission described
above, we hereby offer, to any third party in possession of this jar, the complete corresponding
machine-readable source code, for a charge no more than our cost of physically performing the
distribution. This offer is valid for three years from the date on which this repository last
distributed the jar.** To take us up on it, open an issue at
<https://github.com/MarkLee131/GadgetHunter/issues> or write to the corresponding author at the
address given in the paper.

## Benchmarks referenced by this artifact

`gleipner_results/` contains configurations and outputs produced against the **Gleipner** synthetic
benchmark, which is distributed by its own authors under its own license. This repository does not
redistribute the Gleipner jars themselves. The evaluation in the paper also uses the **ysoserial**
benchmark, which is likewise not redistributed here.
