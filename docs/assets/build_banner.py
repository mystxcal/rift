#!/usr/bin/env python3
"""Generate the RIFT banner.

The scene is a terrain torn by a fault. Everything is derived from one
function -- fault_x(y) -- so the contours, the plate edges, the light and
the wordmark displacement all agree about where the rift is.
"""
import math

W, H = 1600, 900
X0 = 740.0                 # fault centre line
SLIP = 16.0                # vertical displacement of each plate
TOP, BOT = -40.0, 940.0

CYAN = "#7DD3FC"           # plate A / sender
VIOLET = "#BBA6FF"         # plate B / receiver


def wobble(y):
    """The fault's lateral wander: three harmonics, organic but controlled."""
    return (11.0 * math.sin(2 * math.pi * y / 430.0 + 0.7)
            + 5.0 * math.sin(2 * math.pi * y / 170.0 + 2.1)
            + 3.0 * math.sin(2 * math.pi * y / 83.0 + 4.0))


def fault_x(y):
    return X0 + wobble(y)


def contour_x(y, d):
    """A contour line offset d from the fault.

    Near the fault it mimics the fault exactly (the canyon wall follows the
    break). Far away that influence decays and a broader landform takes over.
    """
    damp = math.exp(-abs(d) / 420.0)
    broad = 18.0 * (1.0 - damp) * math.sin(2 * math.pi * y / 700.0 + 1.2)
    return X0 + d + damp * wobble(y) + broad


def smooth_path(pts):
    """Catmull-Rom through pts, emitted as cubic beziers."""
    if len(pts) < 2:
        return ""
    d = "M%.1f,%.1f" % pts[0]
    for i in range(len(pts) - 1):
        p0 = pts[i - 1] if i > 0 else pts[i]
        p1, p2 = pts[i], pts[i + 1]
        p3 = pts[i + 2] if i + 2 < len(pts) else p2
        c1 = (p1[0] + (p2[0] - p0[0]) / 6.0, p1[1] + (p2[1] - p0[1]) / 6.0)
        c2 = (p2[0] - (p3[0] - p1[0]) / 6.0, p2[1] - (p3[1] - p1[1]) / 6.0)
        d += "C%.1f,%.1f %.1f,%.1f %.1f,%.1f" % (c1[0], c1[1], c2[0], c2[1], p2[0], p2[1])
    return d


def sample(fn, step=26.0):
    pts, y = [], TOP
    while y <= BOT:
        pts.append((fn(y), y))
        y += step
    return pts


FAULT_D = smooth_path(sample(fault_x, 22.0))

# Contour offsets: packed tight at the rim, spreading out across the plate.
OFFSETS = [32, 72, 124, 192, 280, 396, 545, 730]


def contours(sign):
    out = []
    for d in OFFSETS:
        dd = d * sign
        op = 0.30 * math.exp(-abs(dd) / 400.0)
        sw = 1.3 if d <= 72 else 1.0
        out.append('<path d="%s" stroke-width="%.2f" stroke-opacity="%.3f"/>'
                   % (smooth_path(sample(lambda y, k=dd: contour_x(y, k))), sw, op))
    return "\n        ".join(out)


# Plate edge: the lit inner face of each wall, just inside the break.
def edge(sign, inset):
    return smooth_path(sample(lambda y: fault_x(y) + sign * inset, 22.0))


STRATA = """
        <path d="M-60,148 H1660" stroke-width="1"   stroke-opacity="0.22"/>
        <path d="M-60,230 H1660" stroke-width="2.4" stroke-opacity="0.46"/>
        <path d="M-60,318 H1660" stroke-width="1"   stroke-opacity="0.19"/>
        <path d="M-60,592 H1660" stroke-width="2.4" stroke-opacity="0.46"/>
        <path d="M-60,678 H1660" stroke-width="1"   stroke-opacity="0.22"/>
        <path d="M-60,766 H1660" stroke-width="1"   stroke-opacity="0.19"/>"""


def plate(sign, colour):
    tint = colour
    return """      <g transform="translate(0,%.0f)">
        <rect x="-60" y="-60" width="1720" height="1020" fill="url(#grid)"/>
        <g fill="none" stroke="%s">
        %s
        </g>
        <g fill="none" stroke="%s">%s
        </g>
        <rect x="-60" y="592" width="1720" height="86" fill="%s" opacity="0.022"/>
      </g>""" % (SLIP * sign, tint, contours(sign), tint, STRATA, tint)


# Where a stratum meets the fault it steps: mark both lips.
def slip_dots():
    out = []
    for y0 in (230, 592):
        for sgn, dy in ((-1, -SLIP), (1, SLIP)):
            y = y0 + dy
            out.append('<circle cx="%.1f" cy="%.1f" r="2.6"/>' % (fault_x(y) + sgn * 4, y))
    return "\n    ".join(out)


CSS = """
    .mono{font-family:"SF Mono","JetBrains Mono","DejaVu Sans Mono",Menlo,Consolas,monospace}
    .flowA{stroke-dasharray:12 16;animation:fa 1.45s linear infinite}
    @keyframes fa{to{stroke-dashoffset:-28}}
    .flowB{stroke-dasharray:5 14;animation:fb 3.8s linear infinite}
    @keyframes fb{to{stroke-dashoffset:-19}}
    .pulse{animation:pl 5.5s ease-in-out infinite}
    @keyframes pl{0%,100%{opacity:.76}50%{opacity:1}}
    .breathe{animation:br 8s ease-in-out infinite}
    @keyframes br{0%,100%{opacity:.60}50%{opacity:1}}
    .twinkle{animation:tw 4.4s ease-in-out infinite}
    @keyframes tw{0%,100%{opacity:.30}50%{opacity:.9}}
    .rays{animation:ry 11s ease-in-out infinite}
    @keyframes ry{0%,100%{opacity:.30}50%{opacity:.62}}
    @media (prefers-reduced-motion:reduce){*{animation:none!important}}
"""

SVG = """<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 1600 900" width="1600" height="900" role="img" aria-label="RIFT - live internet transfer for agents and people">
<title>RIFT - live internet transfer</title>
<desc>A dark technical banner. Terrain rendered in topographic contours is torn by a luminous fault; the strata step across the break and the two plates differ in colour temperature. The wordmark RIFT is split between the I and the F, each half riding its own plate and rim-lit by the light from the rift. Below, two terminal commands are joined by a fast direct path and a slower relay path detouring through a node on the fault.</desc>

<defs>
  <clipPath id="card"><rect x="0" y="0" width="1600" height="900" rx="22"/></clipPath>
  <clipPath id="plateA"><path d="M-40,-40 L{FX_TOP:.1f},-40 {FAULT_TAIL} L-40,940 Z"/></clipPath>
  <clipPath id="plateB"><path d="M1640,-40 L{FX_TOP:.1f},-40 {FAULT_TAIL} L1640,940 Z"/></clipPath>

  <pattern id="grid" width="58" height="58" patternUnits="userSpaceOnUse">
    <path d="M58 0 H0 V58" fill="none" stroke="#9FC4E8" stroke-width="1" stroke-opacity="0.038"/>
  </pattern>

  <radialGradient id="fadeGrad" cx="46%" cy="48%" r="72%">
    <stop offset="0%" stop-color="#fff" stop-opacity="1"/>
    <stop offset="56%" stop-color="#fff" stop-opacity="0.88"/>
    <stop offset="84%" stop-color="#fff" stop-opacity="0.40"/>
    <stop offset="100%" stop-color="#fff" stop-opacity="0"/>
  </radialGradient>
  <mask id="fade"><rect width="1600" height="900" fill="url(#fadeGrad)"/></mask>

  <linearGradient id="seamFadeGrad" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="#fff" stop-opacity="0"/>
    <stop offset="13%" stop-color="#fff" stop-opacity="1"/>
    <stop offset="72%" stop-color="#fff" stop-opacity="1"/>
    <stop offset="92%" stop-color="#fff" stop-opacity="0"/>
  </linearGradient>
  <mask id="seamFade"><rect x="560" y="0" width="380" height="900" fill="url(#seamFadeGrad)"/></mask>

  <!-- rim light falls off with distance from the fault -->
  <linearGradient id="rimFallGrad" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0%" stop-color="#fff" stop-opacity="0.18"/>
    <stop offset="28%" stop-color="#fff" stop-opacity="0.55"/>
    <stop offset="46.25%" stop-color="#fff" stop-opacity="1"/>
    <stop offset="64%" stop-color="#fff" stop-opacity="0.55"/>
    <stop offset="100%" stop-color="#fff" stop-opacity="0.18"/>
  </linearGradient>
  <mask id="rimFall"><rect width="1600" height="900" fill="url(#rimFallGrad)"/></mask>

  <linearGradient id="bgGrad" x1="0" y1="0" x2="1" y2="1">
    <stop offset="0%" stop-color="#070C18"/>
    <stop offset="46%" stop-color="#04050B"/>
    <stop offset="100%" stop-color="#0A0715"/>
  </linearGradient>

  <!-- light thrown sideways onto each wall -->
  <linearGradient id="spillA" x1="1" y1="0" x2="0" y2="0">
    <stop offset="0%" stop-color="#38BDF8" stop-opacity="0.14"/>
    <stop offset="34%" stop-color="#38BDF8" stop-opacity="0.055"/>
    <stop offset="100%" stop-color="#38BDF8" stop-opacity="0"/>
  </linearGradient>
  <linearGradient id="spillB" x1="0" y1="0" x2="1" y2="0">
    <stop offset="0%" stop-color="#B49BFF" stop-opacity="0.17"/>
    <stop offset="34%" stop-color="#A78BFA" stop-opacity="0.055"/>
    <stop offset="100%" stop-color="#A78BFA" stop-opacity="0"/>
  </linearGradient>

  <radialGradient id="cornerA" cx="50%" cy="50%" r="50%">
    <stop offset="0%" stop-color="#22D3EE" stop-opacity="0.11"/>
    <stop offset="100%" stop-color="#22D3EE" stop-opacity="0"/>
  </radialGradient>
  <radialGradient id="cornerB" cx="50%" cy="50%" r="50%">
    <stop offset="0%" stop-color="#8B5CF6" stop-opacity="0.15"/>
    <stop offset="100%" stop-color="#8B5CF6" stop-opacity="0"/>
  </radialGradient>
  <radialGradient id="vignette" cx="50%" cy="46%" r="70%">
    <stop offset="0%" stop-color="#000" stop-opacity="0"/>
    <stop offset="70%" stop-color="#000" stop-opacity="0.15"/>
    <stop offset="100%" stop-color="#000" stop-opacity="0.58"/>
  </radialGradient>
  <radialGradient id="backplate" cx="50%" cy="50%" r="50%">
    <stop offset="0%" stop-color="#03050B" stop-opacity="0.88"/>
    <stop offset="58%" stop-color="#03050B" stop-opacity="0.50"/>
    <stop offset="100%" stop-color="#03050B" stop-opacity="0"/>
  </radialGradient>
  <linearGradient id="aperture" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="#A5F3FC" stop-opacity="0"/>
    <stop offset="30%" stop-color="#67E8F9" stop-opacity="0.80"/>
    <stop offset="66%" stop-color="#818CF8" stop-opacity="0.66"/>
    <stop offset="100%" stop-color="#8B5CF6" stop-opacity="0"/>
  </linearGradient>
  <linearGradient id="rayGrad" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="#9AEBFF" stop-opacity="0.30"/>
    <stop offset="100%" stop-color="#9AEBFF" stop-opacity="0"/>
  </linearGradient>

  <linearGradient id="wmGrad" x1="0" y1="240" x2="0" y2="512" gradientUnits="userSpaceOnUse">
    <stop offset="0%" stop-color="#FFFFFF"/>
    <stop offset="48%" stop-color="#E7EEFF"/>
    <stop offset="100%" stop-color="#9FB6D8"/>
  </linearGradient>
  <linearGradient id="chipFill" x1="0" y1="0" x2="0" y2="1">
    <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.08"/>
    <stop offset="100%" stop-color="#FFFFFF" stop-opacity="0.022"/>
  </linearGradient>

  <filter id="seamWide" x="-600%" y="-8%" width="1300%" height="116%"><feGaussianBlur stdDeviation="22"/></filter>
  <filter id="seamMid" x="-600%" y="-8%" width="1300%" height="116%"><feGaussianBlur stdDeviation="6"/></filter>
  <filter id="seamTight" x="-600%" y="-8%" width="1300%" height="116%"><feGaussianBlur stdDeviation="2.2"/></filter>
  <filter id="chasm" x="-600%" y="-8%" width="1300%" height="116%"><feGaussianBlur stdDeviation="3.5"/></filter>
  <filter id="softLg" x="-70%" y="-60%" width="240%" height="220%"><feGaussianBlur stdDeviation="26"/></filter>
  <filter id="softMd" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="13"/></filter>
  <filter id="softSm" x="-90%" y="-90%" width="280%" height="280%"><feGaussianBlur stdDeviation="5"/></filter>
  <filter id="rayBlur" x="-90%" y="-30%" width="280%" height="160%"><feGaussianBlur stdDeviation="26"/></filter>
  <filter id="grain" x="0" y="0" width="100%" height="100%">
    <feTurbulence type="fractalNoise" baseFrequency="0.9" numOctaves="4" stitchTiles="stitch" result="n"/>
    <feColorMatrix in="n" type="saturate" values="0"/>
  </filter>

  <!-- Wordmark: constructed geometric caps, cap height 250 (y 250-500), stem 46. -->
  <g id="gL">
    <path fill-rule="evenodd" d="M446,250 H641 V400 H492 V500 H446 Z M492,296 H595 V354 H492 Z"/>
    <path d="M547,400 H593 L641,500 H595 Z"/>
    <path d="M675,250 H721 V500 H675 Z"/>
  </g>
  <g id="gR">
    <path d="M755,250 H925 V296 H801 V352 H905 V398 H801 V500 H755 Z"/>
    <path d="M959,250 H1154 V296 H1079 V500 H1033 V296 H959 Z"/>
  </g>

  <path id="pDirect" d="M640,686 C 722,662 878,662 960,686"/>
  <path id="pRelayA" d="M640,686 C 676,750 700,770 740,770"/>
  <path id="pRelayB" d="M740,770 C 782,770 904,748 960,686"/>

  <style>{CSS}</style>
</defs>

<g clip-path="url(#card)">

  <rect width="1600" height="900" fill="url(#bgGrad)"/>
  <ellipse cx="170" cy="110" rx="660" ry="450" fill="url(#cornerA)"/>
  <ellipse cx="1440" cy="820" rx="660" ry="450" fill="url(#cornerB)"/>

  <!-- the two plates: same terrain, displaced, different temperature -->
  <g mask="url(#fade)">
    <g clip-path="url(#plateA)">
{PLATE_A}
    </g>
    <g clip-path="url(#plateB)">
{PLATE_B}
    </g>
  </g>

  <!-- light thrown sideways onto each wall -->
  <g class="breathe">
    <rect x="0" y="0" width="{X0:.0f}" height="900" fill="url(#spillA)" clip-path="url(#plateA)"/>
    <rect x="{X0:.0f}" y="0" width="{XR:.0f}" height="900" fill="url(#spillB)" clip-path="url(#plateB)"/>
  </g>

  <!-- volumetric shafts out of the aperture -->
  <g filter="url(#rayBlur)" class="rays" mask="url(#seamFade)">
    <path d="M735,300 L604,-60 L700,-60 Z" fill="url(#rayGrad)"/>
    <path d="M745,300 L905,-60 L800,-60 Z" fill="url(#rayGrad)"/>
    <path d="M738,470 L640,900 L716,900 Z" fill="url(#rayGrad)" opacity="0.6"/>
    <path d="M746,470 L858,900 L772,900 Z" fill="url(#rayGrad)" opacity="0.6"/>
  </g>

  <!-- the break itself: a chasm with two lit walls -->
  <g mask="url(#seamFade)">
    <path d="{FAULT}" fill="none" stroke="#01020A" stroke-width="10" opacity="0.32" filter="url(#chasm)"/>
    <path d="{EDGE_L}" fill="none" stroke="{CYAN}" stroke-width="1.9" opacity="0.55" clip-path="url(#plateA)"/>
    <path d="{EDGE_R}" fill="none" stroke="{VIOLET}" stroke-width="1.9" opacity="0.60" clip-path="url(#plateB)"/>
    <path d="{FAULT}" fill="none" stroke="#7C3AED" stroke-width="22" opacity="0.36" filter="url(#seamWide)"/>
    <path d="{FAULT}" fill="none" stroke="#22D3EE" stroke-width="7" opacity="0.38" filter="url(#seamMid)"/>
  </g>

  <ellipse cx="{X0:.0f}" cy="392" rx="26" ry="212" fill="url(#aperture)" filter="url(#softLg)" opacity="0.88" class="pulse"/>
  <ellipse cx="{X0:.0f}" cy="400" rx="505" ry="214" fill="url(#backplate)"/>
  <ellipse cx="{X0:.0f}" cy="396" rx="11" ry="120" fill="#DFFBFF" filter="url(#softMd)" opacity="0.55" class="pulse"/>

  <g mask="url(#seamFade)">
    <path d="{FAULT}" fill="none" stroke="#A5F3FC" stroke-width="2.6" opacity="0.44" filter="url(#seamTight)"/>
    <path d="{FAULT}" fill="none" stroke="#EAFDFF" stroke-width="1.15" opacity="0.88" class="pulse"/>
  </g>

  <g fill="#BEF3FA">
    {SLIPDOTS}
  </g>

  <!-- wordmark: each half rides its own plate and is rim-lit by the rift -->
  <g filter="url(#softMd)" opacity="0.24" fill="#38BDF8">
    <use xlink:href="#gL" href="#gL" transform="translate(0,-11)"/>
    <use xlink:href="#gR" href="#gR" transform="translate(0,11)"/>
  </g>
  <g mask="url(#rimFall)">
    <g fill="#E4FDFF"><use xlink:href="#gL" href="#gL" transform="translate(5,-11)"/></g>
    <g fill="#F6F3FF"><use xlink:href="#gR" href="#gR" transform="translate(-5,11)"/></g>
  </g>
  <g fill="url(#wmGrad)">
    <use xlink:href="#gL" href="#gL" transform="translate(0,-11)"/>
    <use xlink:href="#gR" href="#gR" transform="translate(0,11)"/>
  </g>

  <text class="mono" x="800" y="576" text-anchor="middle" font-size="20" letter-spacing="4.6"
        fill="#93AAC6">LIVE INTERNET TRANSFER FOR AGENTS AND PEOPLE</text>

  <!-- endpoints -->
  <rect x="150" y="648" width="490" height="76" rx="14" fill="url(#chipFill)" stroke="#FFFFFF" stroke-opacity="0.14"/>
  <text class="mono" x="395" y="695" text-anchor="middle" font-size="27" fill="#D7E3F3"><tspan fill="#43607F">$ </tspan>rift send <tspan fill="#A5F3FC">archive.tar</tspan></text>
  <rect x="960" y="648" width="490" height="76" rx="14" fill="url(#chipFill)" stroke="#FFFFFF" stroke-opacity="0.14"/>
  <text class="mono" x="1205" y="695" text-anchor="middle" font-size="27" fill="#D7E3F3"><tspan fill="#43607F">$ </tspan>rift receive <tspan fill="#67E8F9">4827-lumeko</tspan></text>

  <!-- the race across the rift -->
  <g fill="none" stroke-linecap="round">
    <use xlink:href="#pRelayA" href="#pRelayA" stroke="#8B5CF6" stroke-width="1.8" opacity="0.55" class="flowB"/>
    <use xlink:href="#pRelayB" href="#pRelayB" stroke="#8B5CF6" stroke-width="1.8" opacity="0.55" class="flowB"/>
    <use xlink:href="#pDirect" href="#pDirect" stroke="#22D3EE" stroke-width="9" opacity="0.22" filter="url(#softSm)"/>
    <use xlink:href="#pDirect" href="#pDirect" stroke="#7DEAF8" stroke-width="2.8" opacity="0.97" class="flowA"/>
  </g>
  <g>
    <circle cx="640" cy="686" r="3.2" fill="#A5F3FC"/><circle cx="960" cy="686" r="3.2" fill="#A5F3FC"/>
    <circle cx="740" cy="770" r="9" fill="#0A0918" stroke="#8B5CF6" stroke-opacity="0.9" stroke-width="1.6"/>
    <circle cx="740" cy="770" r="2.6" fill="#C4B5FD"/>
    <circle r="3.8" fill="#F0FEFF"><animateMotion dur="2.1s" repeatCount="indefinite" begin="0s"><mpath xlink:href="#pDirect" href="#pDirect"/></animateMotion></circle>
    <circle r="3.1" fill="#A5F3FC" opacity="0.82"><animateMotion dur="2.1s" repeatCount="indefinite" begin="-0.7s"><mpath xlink:href="#pDirect" href="#pDirect"/></animateMotion></circle>
    <circle r="2.6" fill="#67E8F9" opacity="0.66"><animateMotion dur="2.1s" repeatCount="indefinite" begin="-1.4s"><mpath xlink:href="#pDirect" href="#pDirect"/></animateMotion></circle>
    <circle r="2.3" fill="#C4B5FD" opacity="0.62"><animateMotion dur="4.1s" repeatCount="indefinite" begin="0s"><mpath xlink:href="#pRelayA" href="#pRelayA"/></animateMotion></circle>
    <circle r="2.3" fill="#C4B5FD" opacity="0.62"><animateMotion dur="4.1s" repeatCount="indefinite" begin="-2.05s"><mpath xlink:href="#pRelayB" href="#pRelayB"/></animateMotion></circle>
  </g>
  <text class="mono" x="884" y="642" text-anchor="middle" font-size="14" letter-spacing="2.6" fill="#7FE3F0" opacity="0.92">DIRECT</text>
  <text class="mono" x="612" y="798" text-anchor="middle" font-size="14" letter-spacing="2.6" fill="#9585CE" opacity="0.88">RELAY</text>

  <!-- technical furniture -->
  <g class="mono">
    <path d="M78,86 l7,-7 7,7 -7,7 Z" fill="#22D3EE" opacity="0.9"/>
    <text x="106" y="93" font-size="16" letter-spacing="2.6" fill="#61809F">OPEN SOURCE &#183; RUST &#183; MIT</text>
    <text x="1522" y="93" font-size="16" letter-spacing="2.6" text-anchor="end" fill="#61809F">SPAKE2 &#183; NOISE &#183; BLAKE3</text>
    <text x="800" y="858" font-size="16" letter-spacing="1.6" text-anchor="middle" fill="#566F91">direct and relayed paths raced &#183; one-pass authenticated object graph &#183; atomic commit</text>
    <text transform="translate(48,468) rotate(-90)" text-anchor="middle" font-size="13" letter-spacing="3.4" fill="#3E5878">PLATE A &#8212; SENDER</text>
    <text transform="translate(1552,468) rotate(90)" text-anchor="middle" font-size="13" letter-spacing="3.4" fill="#4A4173">PLATE B &#8212; RECEIVER</text>
  </g>
  <g stroke="#FFFFFF" stroke-opacity="0.20" stroke-width="1" fill="none">
    <path d="M34,62 V34 H62"/><path d="M1538,34 H1566 V62"/>
    <path d="M34,838 V866 H62"/><path d="M1538,866 H1566 V838"/>
  </g>

  <rect width="1600" height="900" fill="url(#vignette)"/>
  <rect width="1600" height="900" filter="url(#grain)" opacity="0.05" style="mix-blend-mode:overlay"/>
  <rect x="0.5" y="0.5" width="1599" height="899" rx="22" fill="none" stroke="#FFFFFF" stroke-opacity="0.10"/>
</g>
</svg>
"""

# The clip paths reuse the fault, entered from the top corner.
fault_tail = FAULT_D[1:]  # drop the leading M; we arrive by L from the corner
fault_tail = "L" + fault_tail.split("C", 1)[0] + "C" + fault_tail.split("C", 1)[1]

out = (SVG
       .replace("{CSS}", CSS)
       .replace("{FAULT_TAIL}", fault_tail)
       .replace("{FAULT}", FAULT_D)
       .replace("{EDGE_L}", edge(-1, 8.0))
       .replace("{EDGE_R}", edge(1, 8.0))
       .replace("{PLATE_A}", plate(-1, CYAN))
       .replace("{PLATE_B}", plate(1, VIOLET))
       .replace("{SLIPDOTS}", slip_dots())
       .replace("{FX_TOP:.1f}", "%.1f" % fault_x(TOP))
       .replace("{X0:.0f}", "%.0f" % X0)
       .replace("{XR:.0f}", "%.0f" % (W - X0))
       .replace("{CYAN}", CYAN)
       .replace("{VIOLET}", VIOLET))

with open("banner.svg", "w") as f:
    f.write(out)
print("wrote banner.svg  %.1f KB" % (len(out) / 1024.0))
