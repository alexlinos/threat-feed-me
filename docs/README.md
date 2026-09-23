# Threat Feed Me!

Static marketing page served at https://threatfeedme.app via GitHub Pages
(Settings → Pages → Source: `main` branch, `/docs` folder).

Self-contained: `index.html` plus the brand assets in `assets/` (copied from the
repo-root `assets/`). No build step, no dependencies, no backend.

There is no `CNAME` file: `threatfeedme.app` is a registrar-level redirect to
the github.io address, which drops the path, so the page's canonical and social
tags use absolute github.io URLs. To serve the site on the custom domain
properly, point the domain's DNS at GitHub Pages first, then add `CNAME` here;
adding `CNAME` while the redirect is still in place creates a redirect loop.
See the repo README for the product itself.
