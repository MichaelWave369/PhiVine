# ΦVine

**A local-first compatibility planner for PhiOS.**

PhiVine is an experimental project to help PhiOS users assess and eventually run selected Windows applications on a Linux-based PhiOS desktop by integrating established compatibility engines such as Wine. It is **not** a replacement implementation of Wine.

## Status

**Rung 1: advisory-only foundation (in development).** No Windows executable installation or execution is currently implemented. No security sandbox or isolation is claimed. The PhiOS Linux target itself remains an alpha development preview.

## Principles

- **Capability is not authority.** Inspection, detection, and compatibility recommendations never grant installation or execution permission.
- **Offline by default.** No network calls or downloads during inspection.
- **Explain before acting.** Produce reproducible, typed evidence and specific blockers.
- **Reuse, don't counterfeit.** Wine/Proton and their licenses remain independent upstream components; no runtime is bundled.
- **Fail closed.** Unknown formats and missing runners are held rather than treated as supported.

The initial architecture and a small standard-library Python CLI are being developed in a pull request. See the Rung 1 contract for precise limitations once merged.

## Relationship to PhiOS

PhiOS App Platform v0.58 profiles public *repositories* and classifies source build paths. PhiVine's planned inspection addresses a distinct input: a local Windows PE executable or MSI package. Integration is **proposed**, not yet implemented.

## License

MIT for original PhiVine code and documentation. Third-party executables and compatibility runtimes keep their own licenses.
