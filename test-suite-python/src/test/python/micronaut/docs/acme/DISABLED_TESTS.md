# Python Docs Disabled Test Inventory

This file tracks the Python documentation examples of Micronaut ACME under `test-suite-python/src/test/python/micronaut/docs/acme`
that are disabled, or that carry a workaround because the direct port of the Java example does not compile or does not behave
like the Java example yet (Python compiler gaps). It is the bug-fixing task list for the Python compiler
(`micronaut-inject-python` / `micronaut-context-python`); every row references a `TODO(python)` comment in the sources.

The Python examples are compiled by every build and their tests run with `./gradlew pythonCheck -Ppython-ci`
(the "Python CI" GitHub workflow).

## Reconciliation

- Last generated active `@Disabled` count: 0.
- Last generated command: `rg -n "@Disabled\(" test-suite-python/src/test/python`.
- Last full-suite command: `./gradlew :test-suite-python:test -Ppython-ci`.
- Last full-suite result: build successful, 2 tests executed (1 test class), 0 skipped.

## Migration Rules

- The snippet classes live in `io.micronaut.docs.acme` in every language (not `io.micronaut.acme.docs`): the module's
  `io.micronaut.acme` package carries a package-level `@Configuration @Requires(property = "acme.enabled")`, which
  Micronaut applies to every bean in its sub-packages, so JVM test beans placed under `io.micronaut.acme` are disabled
  unless the whole ACME integration is configured.
- `CustomDnsChallengeSolver` subclasses the imported Java interface `DnsChallengeSolver`, keeps the Java method names
  (`createRecord`, `destroyRecord`) and uses `pass` bodies (an `...` body would make the bean class abstract);
  `@Replaces(DnsChallengeSolver)` takes the imported class as its value.
- A Python test class is a `@MicronautTest` with `@Test` methods and plain `assert` statements; the test asserts that the
  injected `DnsChallengeSolver` is the custom solver and the only solver bean, and calls both methods.

## Active `@Disabled` Tests

None.

## Workarounds in the Sources

None.

## `java.type` usages

| Target | Reason |
| --- | --- |
| `CustomDnsChallengeSolverTest` (`DnsChallengeSolverType = java.type("io.micronaut.acme.challenge.dns.DnsChallengeSolver")`, `CustomDnsChallengeSolverType = java.type("micronaut.docs.acme.CustomDnsChallengeSolver")`) | only a `java.type(...)` alias can be used as the runtime type argument of `context.getBeansOfType(...)` and of the `isinstance(...)` check (imported shim classes only work as type hints, generic bases and annotation members). |
