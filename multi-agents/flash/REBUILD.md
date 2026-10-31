# Rebuilding the Stage-1 backend (flash.jar)

`flash.jar` is the Stage-1 gadget-chain miner, a Tai-e build with the deserialization
analysis and the JVM-instruction edge info the LLM stage consumes. It is vendored because
it is a maintained fork, not an upstream artifact. To rebuild it (for example to raise the
parseable Java version):

1. Clone the maintained source: `MarkLee131/flash_self-maintained` (Tai-e 0.5.1 base).
2. The repository omits `src/main/java/pascal/taie/frontend/cache/` (two upstream caching
   classes). Supply `CachedWorldBuilder.java` and `CachedIRBuilder.java`; if upstream master
   does not match the fork's API, decompile them from the previous `flash.jar`. One
   decompilation fix is needed: declare `ArrayList<String> paths` in `CachedWorldBuilder`.
3. The parseable target Java version is set by the ASM dependency in `build.gradle.kts`.
   `org.ow2.asm:asm:9.4` reads up to Java 20; `9.6` reads up to Java 22.
4. Build with a JDK 17 toolchain:
   `JAVA_HOME=<jdk17> ./gradlew fatJar -Dorg.gradle.java.home=<jdk17>`
   The jar lands in `build/`.
5. After replacing `flash.jar`, update `backend/strings/compatibility.json` with the new
   `backend_sha256` (the overlay refuses an unrecognized backend). Then revalidate: run the
   full test suite and `benchmark_recall.py`; the recall benchmark must not regress before
   the change is committed.

The current `flash.jar` is built with ASM 9.6, so targets up to Java 22 parse.
