"""Generates the Thawr logo SVGs: a cave arch built from a node mesh
sheltering a smaller mesh, plus the wordmark. Hand-tuned geometry."""
import math

NAVY = "#0b2233"
BLUES = ["#1d4f7a", "#24678f", "#2b8aa8", "#3aaebf", "#4fc3c8"]
TEAL = "#3fb8c4"
WHITE = "#ffffff"

CX, CY = 200.0, 190.0
R1, R2 = 132.0, 88.0
FOOT = 38.0


def pt(r, deg):
    a = math.radians(deg)
    return (CX + r * math.cos(a), CY - r * math.sin(a))


def fmt(p):
    return f"{p[0]:.1f},{p[1]:.1f}"


def band_polys():
    """Triangulate the band between outer and inner arcs by merging the
    two rings ordered by angle, so triangles stay slim and regular."""
    outer = [(180 - 22.5 * i) for i in range(9)]
    inner = [(180 - 30 * i) for i in range(7)]
    o = [("o", a) for a in outer]
    i_ = [("i", a) for a in inner]
    seq = sorted(o + i_, key=lambda t: -t[1])  # from 180 down to 0
    tris = []
    last_o = last_i = None
    for ring, ang in seq:
        p = pt(R1, ang) if ring == "o" else pt(R2, ang)
        if ring == "o":
            if last_o is not None and last_i is not None:
                tris.append((last_o, last_i, p))
            last_o = p
        else:
            if last_i is not None and last_o is not None:
                tris.append((last_i, last_o, p))
            last_i = p
    return tris, [pt(R1, a) for a in outer], [pt(R2, a) for a in inner]


def mark(x=0, y=0, scale=1.0, inner_mesh=True, node_r=4.2):
    tris, outer_pts, inner_pts = band_polys()
    parts = [f'<g transform="translate({x},{y}) scale({scale})">']
    # cave interior
    li, ri = pt(R2, 180), pt(R2, 0)
    parts.append(
        f'<path d="M{fmt(li)} A{R2},{R2} 0 0 1 {fmt(ri)} '
        f'L{ri[0]:.1f},{CY + FOOT:.1f} L{li[0]:.1f},{CY + FOOT:.1f} Z" fill="{NAVY}"/>'
    )
    # feet (quads extending the band down)
    lo, ro = pt(R1, 180), pt(R1, 0)
    for k, (a, b) in enumerate(((lo, li), (ri, ro))):
        colour = BLUES[0] if k == 0 else BLUES[4]
        parts.append(
            f'<polygon points="{fmt(a)} {fmt(b)} {b[0]:.1f},{CY + FOOT:.1f} '
            f'{a[0]:.1f},{CY + FOOT:.1f}" '
            f'fill="{colour}" stroke="{WHITE}" stroke-width="2" stroke-linejoin="round"/>'
        )
    # band triangles, colour drifts from deep blue (left) to teal (right)
    n = len(tris)
    for idx, t in enumerate(tris):
        colour = BLUES[min(4, int(idx * 5 / n))]
        if idx % 2:
            colour = BLUES[min(4, int(idx * 5 / n) + 1)] if idx * 5 // n < 4 else BLUES[3]
        parts.append(
            f'<polygon points="{fmt(t[0])} {fmt(t[1])} {fmt(t[2])}" fill="{colour}" '
            f'stroke="{WHITE}" stroke-width="2" stroke-linejoin="round"/>'
        )
    # nodes
    for p in outer_pts + inner_pts + [(lo[0], CY + FOOT), (ro[0], CY + FOOT), (li[0], CY + FOOT), (ri[0], CY + FOOT)]:
        parts.append(f'<circle cx="{p[0]:.1f}" cy="{p[1]:.1f}" r="{node_r}" fill="{WHITE}"/>')
    if inner_mesh:
        nodes = [(200, 140), (163, 168), (237, 166), (182, 204), (222, 206), (200, 178), (170, 222), (232, 226)]
        edges = [(0, 1), (0, 2), (0, 5), (1, 3), (1, 5), (2, 4), (2, 5), (3, 5), (4, 5), (3, 4), (3, 6), (4, 7), (6, 7)]
        for a, b in edges:
            parts.append(
                f'<line x1="{nodes[a][0]}" y1="{nodes[a][1]}" x2="{nodes[b][0]}" y2="{nodes[b][1]}" '
                f'stroke="{WHITE}" stroke-width="1.6" stroke-opacity="0.85"/>'
            )
        for k, p in enumerate(nodes):
            fill = TEAL if k in (0, 5, 3, 4) else WHITE
            parts.append(f'<circle cx="{p[0]}" cy="{p[1]}" r="4.6" fill="{fill}" stroke="{WHITE}" stroke-width="1.6"/>')
    parts.append("</g>")
    return "\n".join(parts)


FONT = "Inter, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif"


def logo(text_fill, tagline=False):
    h = 400 if tagline else 372
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 400 {h}" width="400" height="{h}" role="img" aria-label="Thawr">',
        "<title>Thawr</title>",
        mark(),
        f'<text x="200" y="322" text-anchor="middle" font-family="{FONT}" font-size="76" font-weight="800" '
        f'letter-spacing="6" fill="{text_fill}">THAWR</text>',
    ]
    if tagline:
        out.append(
            f'<text x="200" y="356" text-anchor="middle" font-family="{FONT}" font-size="13" font-weight="500" '
            f'letter-spacing="1.5" fill="{text_fill}" fill-opacity="0.85">ONE BINARY · NO CLOUD · WORKS OFFLINE</text>'
        )
    out.append("</svg>")
    return "\n".join(out)


def icon():
    """Simplified mark for favicons: one thick arch with five nodes and a
    three-node mesh inside, on a navy tile. Reads down to 16 px."""
    cx, cy, r = 32.0, 36.0, 19.0
    arc_pts = [pt_at(cx, cy, r, a) for a in (180, 135, 90, 45, 0)]
    path = f"M{cx - r:.1f},{cy + 12:.1f} L{cx - r:.1f},{cy:.1f} A{r},{r} 0 0 1 {cx + r:.1f},{cy:.1f} L{cx + r:.1f},{cy + 12:.1f}"
    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="64" height="64" role="img" aria-label="Thawr">',
        f'<rect width="64" height="64" rx="12" fill="{NAVY}"/>',
        '<defs><linearGradient id="g" x1="0" y1="0" x2="1" y2="0">'
        f'<stop offset="0" stop-color="{BLUES[0]}"/><stop offset="1" stop-color="{BLUES[4]}"/></linearGradient></defs>',
        f'<path d="{path}" fill="none" stroke="url(#g)" stroke-width="9" stroke-linecap="butt"/>',
    ]
    for p in arc_pts:
        out.append(f'<circle cx="{p[0]:.1f}" cy="{p[1]:.1f}" r="3" fill="{WHITE}"/>')
    tri = [(32, 33), (25, 43), (39, 43)]
    for a, b in ((0, 1), (0, 2), (1, 2)):
        out.append(f'<line x1="{tri[a][0]}" y1="{tri[a][1]}" x2="{tri[b][0]}" y2="{tri[b][1]}" stroke="{WHITE}" stroke-width="1.6"/>')
    out.append(f'<circle cx="32" cy="33" r="3.2" fill="{TEAL}"/>')
    out.append(f'<circle cx="25" cy="43" r="2.6" fill="{WHITE}"/>')
    out.append(f'<circle cx="39" cy="43" r="2.6" fill="{WHITE}"/>')
    out.append("</svg>")
    return "\n".join(out)


def social():
    """1280x640 social preview: navy card, mark left, wordmark and
    tagline right. GitHub shows it on links to the repository."""
    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1280 640" width="1280" height="640" role="img" aria-label="Thawr">',
        "<title>Thawr</title>",
        f'<rect width="1280" height="640" fill="{NAVY}"/>',
        # subtle mesh in the background corners
        f'<g stroke="{WHITE}" stroke-opacity="0.08" stroke-width="2">'
        '<line x1="0" y1="560" x2="220" y2="420"/><line x1="220" y1="420" x2="380" y2="560"/>'
        '<line x1="220" y1="420" x2="300" y2="220"/><line x1="1280" y1="60" x2="1160" y2="150"/>'
        '<line x1="1160" y1="150" x2="1040" y2="40"/><line x1="1160" y1="150" x2="1240" y2="300"/></g>',
        f'<g fill="{WHITE}" fill-opacity="0.18"><circle cx="220" cy="420" r="6"/><circle cx="300" cy="220" r="6"/>'
        '<circle cx="380" cy="560" r="6"/><circle cx="1160" cy="150" r="6"/><circle cx="1040" cy="40" r="6"/>'
        '<circle cx="1240" cy="300" r="6"/></g>',
        mark(x=80, y=100, scale=1.1),
        f'<text x="560" y="300" font-family="{FONT}" font-size="120" font-weight="800" '
        f'letter-spacing="8" fill="{WHITE}">THAWR</text>',
        f'<text x="566" y="366" font-family="{FONT}" font-size="24" font-weight="500" '
        f'letter-spacing="2" fill="{WHITE}" fill-opacity="0.85">ONE BINARY · NO CLOUD · WORKS OFFLINE</text>',
        f'<text x="566" y="430" font-family="{FONT}" font-size="26" font-weight="400" '
        f'fill="{WHITE}" fill-opacity="0.7">Self-hosted WireGuard mesh VPN and ZTNA.</text>',
        f'<text x="566" y="468" font-family="{FONT}" font-size="26" font-weight="400" '
        f'fill="{WHITE}" fill-opacity="0.7">Local users, one-time tokens, ACLs in git, relay built in.</text>',
        f'<text x="566" y="540" font-family="{FONT}" font-size="22" font-weight="500" '
        f'letter-spacing="1" fill="{TEAL}">github.com/Sira-Labs/Thawr</text>',
        "</svg>",
    ]
    return "\n".join(out)


def pt_at(cx, cy, r, deg):
    a = math.radians(deg)
    return (cx + r * math.cos(a), cy - r * math.sin(a))


open("docs/assets/logo-dark.svg", "w").write(logo(WHITE))
open("docs/assets/logo-light.svg", "w").write(logo(NAVY))
open("docs/assets/logo-tagline-dark.svg", "w").write(logo(WHITE, tagline=True))
open("docs/assets/mark.svg", "w").write(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="40 40 320 200" width="320" height="200" role="img" aria-label="Thawr mark">\n'
    + mark() + "\n</svg>")
open("docs/assets/icon.svg", "w").write(icon())
open("docs/assets/social-preview.svg", "w").write(social())
print("written")
