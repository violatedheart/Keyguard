# Documentation images

The README uses four PNGs with editable, self-contained SVG counterparts:

| Image | Purpose |
| --- | --- |
| [Quick start](images/quickstart.png) / [SVG](images/quickstart.svg) | Run the standalone executable, inspect a PID, export a report, and interpret risk tiers |
| [Architecture](images/architecture.png) / [SVG](images/architecture.svg) | Understand metadata collection, configured scoring, allowlists, and reports |
| [Scan example](images/scan-example.png) / [SVG](images/scan-example.svg) | Recognize the CLI table, default filtering, and coverage notes |
| [Inspect example](images/inspect-example.png) / [SVG](images/inspect-example.svg) | Read individual findings and weights |

**The terminal examples contain only invented process records.** They use the
real `show_scan` and `show_process` renderers and the real default scoring engine;
they do not scan a system, query key state, execute the probes, create startup
entries, or make network connections. The inspect image is explicitly an excerpt
before the JSON observations. The decorative terminal frame is rendered by Rich;
it is not a screenshot of a Windows desktop.

The sample High score is `18 + 18 + 20 + 3 + 12 = 71`; the sample Medium score is
`18 + 18 + 20 = 56`. These are demonstrations of the default weights, not malware
classifications. No real process or publisher is depicted as malicious.

Regenerate SVGs after installing KeyGuard in your development environment:

```powershell
python docs/render_assets.py
```

To also create PNGs, install the [Inkscape CLI](https://inkscape.org/) and ensure
`inkscape` is on PATH:

```powershell
python docs/render_assets.py --png
```

PNGs render at 1800 pixels wide. The renderer uses DejaVu fonts when installed,
with system sans-serif/monospace fallbacks. PNGs provide consistent GitHub display;
the SVGs contain accessible titles/descriptions and no remote font or image assets.
No image service or extra Python imaging dependency is required to regenerate them.
All images and their source are covered by the repository's MIT license.
