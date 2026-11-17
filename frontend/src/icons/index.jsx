import { forwardRef } from "react";

/*
 * CyberShield's own flat, colourful icon set. Every icon is drawn on the same
 * 24px grid from the same small palette (CSS variables in index.css), so the
 * set reads as one family in both themes. Exports keep the names of the
 * icons they replaced, so call sites only change their import path.
 *
 * Props match what the app already passes: size, className, title, and
 * aria-* attributes. Icons are decorative (aria-hidden) unless given a title.
 * strokeWidth and color are accepted and ignored: these icons are filled.
 */

const C = {
  teal: "var(--ico-teal)",
  tealD: "var(--ico-teal-d)",
  blue: "var(--ico-blue)",
  blueD: "var(--ico-blue-d)",
  coral: "var(--ico-coral)",
  coralD: "var(--ico-coral-d)",
  amber: "var(--ico-amber)",
  amberD: "var(--ico-amber-d)",
  green: "var(--ico-green)",
  greenD: "var(--ico-green-d)",
  slate: "var(--ico-slate)",
  slateD: "var(--ico-slate-d)",
  navy: "var(--ico-navy)",
  paper: "var(--ico-paper)",
  paperD: "var(--ico-paper-d)",
  cut: "var(--ico-cut)",
  white: "#fff",
};

// White detail strokes drawn on top of a filled shape.
const W = { fill: "none", stroke: C.white, strokeWidth: 2.2, strokeLinecap: "round", strokeLinejoin: "round" };
const line = (color, width = 2.2) => ({ fill: "none", stroke: color, strokeWidth: width, strokeLinecap: "round", strokeLinejoin: "round" });

function toKebab(name) {
  return name.replace(/([a-z0-9])([A-Z])/g, "$1-$2").toLowerCase();
}

function makeIcon(name, draw) {
  const Icon = forwardRef(function FlatIcon(
    { size = 24, className, title, strokeWidth: _strokeWidth, color: _color, fill, ...rest },
    ref,
  ) {
    const labelled = Boolean(title) || Boolean(rest["aria-label"]);
    return (
      <svg
        ref={ref}
        width={size}
        height={size}
        viewBox="0 0 24 24"
        className={["flat-icon", `flat-icon-${toKebab(name)}`, className].filter(Boolean).join(" ")}
        aria-hidden={labelled ? undefined : true}
        role={labelled ? "img" : undefined}
        focusable="false"
        {...rest}
      >
        {title && <title>{title}</title>}
        {draw({ fill })}
      </svg>
    );
  });
  Icon.displayName = name;
  return Icon;
}

/* ---- shared parts ------------------------------------------------------ */

const Disc = ({ color }) => <circle cx="12" cy="12" r="11" fill={color} />;
const Tile = ({ color }) => <rect x="2" y="2" width="20" height="20" rx="5.5" fill={color} />;

const SHIELD = "M12 1.5 3.5 4.8v6.4c0 5.3 3.6 9.6 8.5 11.3 4.9-1.7 8.5-6 8.5-11.3V4.8z";
const SHIELD_SHADE = "M12 1.5v21c4.9-1.7 8.5-6 8.5-11.3V4.8z";
function Shield({ color, shade, children }) {
  return (
    <>
      <path d={SHIELD} fill={color} />
      <path d={SHIELD_SHADE} fill={shade} />
      {children}
    </>
  );
}

function Page({ lines = C.blue }) {
  return (
    <>
      <path d="M6 1.5h8.5L20 7v14a1.5 1.5 0 0 1-1.5 1.5h-12A1.5 1.5 0 0 1 4.5 21V3A1.5 1.5 0 0 1 6 1.5z" fill={C.paper} />
      <path d="M14.5 1.5V6a1 1 0 0 0 1 1H20z" fill={C.paperD} />
      {lines && (
        <>
          <rect x="7.5" y="10" width="9" height="1.8" rx=".9" fill={lines} />
          <rect x="7.5" y="13.6" width="9" height="1.8" rx=".9" fill={lines} />
          <rect x="7.5" y="17.2" width="5.5" height="1.8" rx=".9" fill={lines} />
        </>
      )}
    </>
  );
}

// A small round badge in the lower-right corner, cut out from what is under it.
const BADGE_GLYPHS = {
  check: "M-2.4.2-.8 1.8 2.4-1.6",
  plus: "M0-2.6v5.2M-2.6 0h5.2",
  up: "M0 2.6v-5M-2.2-.4 0-2.6 2.2-.4",
  clock: "M0-2.6V0l1.8 1.2",
  code: "M-1.2-2.4-3 0l1.8 2.4M1.2-2.4 3 0l-1.8 2.4",
  search: "M1 1l1.8 1.8",
};
function Badge({ color, glyph, cx = 17.5, cy = 17.5 }) {
  return (
    <g transform={`translate(${cx} ${cy})`}>
      <circle r="6" fill={color} stroke={C.cut} strokeWidth="1.5" />
      {glyph === "search" && <circle cx="-.6" cy="-.6" r="2.1" {...line(C.white, 1.7)} />}
      {glyph === "gear" ? (
        <g transform="scale(.42) translate(-12 -12)"><GearShape color={C.white} hub={color} /></g>
      ) : (
        <path d={BADGE_GLYPHS[glyph]} {...line(C.white, 1.8)} />
      )}
    </g>
  );
}

function GearShape({ color, hub }) {
  return (
    <>
      {Array.from({ length: 8 }, (_, index) => (
        <rect key={index} x="10.3" y="1.5" width="3.4" height="4.6" rx=".9" fill={color} transform={`rotate(${index * 45} 12 12)`} />
      ))}
      <circle cx="12" cy="12" r="7.2" fill={color} />
      <circle cx="12" cy="12" r="2.9" fill={hub} />
    </>
  );
}

function Person({ head, body, x = 0, scale = 1 }) {
  return (
    <g transform={`translate(${x} 0) translate(12 12) scale(${scale}) translate(-12 -12)`}>
      <circle cx="12" cy="7.8" r="4.6" fill={head} />
      <path d="M3.5 21.5a8.5 7.2 0 0 1 17 0z" fill={body} />
    </g>
  );
}

function Envelope({ color = C.blue }) {
  return (
    <>
      <rect x="2" y="4.5" width="20" height="15" rx="2.5" fill={color} />
      <path d="M3 6.2 12 13l9-6.8" {...line(C.white, 2)} />
    </>
  );
}

const BELL = "M12 2.5a6 6 0 0 1 6 6v4.2l1.8 3.1a1 1 0 0 1-.9 1.5H5.1a1 1 0 0 1-.9-1.5L6 12.7V8.5a6 6 0 0 1 6-6z";

/* ---- arrows and controls ----------------------------------------------- */

// Solid block arrows in the surrounding text colour, so they read on teal
// links, filled buttons and both themes alike.
const BLOCK_ARROW = "M1 10h11V5l11 7-11 7v-5H1z";
export const ArrowRight = makeIcon("ArrowRight", () => <path d={BLOCK_ARROW} fill="currentColor" />);
export const ArrowLeft = makeIcon("ArrowLeft", () => <path d={BLOCK_ARROW} fill="currentColor" transform="rotate(180 12 12)" />);
export const ArrowUpRight = makeIcon("ArrowUpRight", () => <path d={BLOCK_ARROW} fill="currentColor" transform="rotate(-45 12 12) scale(.92) translate(1 1)" />);
export const ExternalLink = makeIcon("ExternalLink", () => <><Disc color={C.blue} /><path d="M13 7h4v4M17 7l-6 6M15 13.5V17H7V9h3.5" {...W} strokeWidth="2" /></>);
export const ChevronRight = makeIcon("ChevronRight", () => <><Disc color={C.slate} /><path d="M10 7l5 5-5 5" {...W} /></>);
export const ChevronLeft = makeIcon("ChevronLeft", () => <><Disc color={C.slate} /><path d="M14 7l-5 5 5 5" {...W} /></>);
export const ChevronDown = makeIcon("ChevronDown", () => <><Disc color={C.slate} /><path d="M7 10l5 5 5-5" {...W} /></>);
export const X = makeIcon("X", () => <><Disc color={C.coral} /><path d="M8 8l8 8M16 8l-8 8" {...W} /></>);
export const CircleX = makeIcon("CircleX", () => <><Disc color={C.coral} /><path d="M8 8l8 8M16 8l-8 8" {...W} /></>);
const drawCheck = () => <><Disc color={C.green} /><path d="M7 12.5l3.2 3.2L17 9" {...W} strokeWidth="2.5" /></>;
export const Check = makeIcon("Check", drawCheck);
export const CircleCheck = makeIcon("CircleCheck", drawCheck);
export const CheckCircle2 = makeIcon("CheckCircle2", drawCheck);
export const CircleCheckBig = makeIcon("CircleCheckBig", drawCheck);
export const Plus = makeIcon("Plus", () => <><Disc color={C.teal} /><path d="M12 7v10M7 12h10" {...W} strokeWidth="2.5" /></>);
export const Menu = makeIcon("Menu", () => <><Tile color={C.slate} /><path d="M7 8h10M7 12h10M7 16h10" {...W} /></>);
export const Play = makeIcon("Play", () => <><Disc color={C.teal} /><path d="M10 8.2v7.6a.6.6 0 0 0 .9.5l6-3.8a.6.6 0 0 0 0-1l-6-3.8a.6.6 0 0 0-.9.5z" fill={C.white} /></>);
export const PlayCircle = makeIcon("PlayCircle", () => <><Disc color={C.teal} /><path d="M10 8.2v7.6a.6.6 0 0 0 .9.5l6-3.8a.6.6 0 0 0 0-1l-6-3.8a.6.6 0 0 0-.9.5z" fill={C.white} /></>);
export const Pause = makeIcon("Pause", () => <><Disc color={C.amber} /><rect x="8.3" y="7.5" width="2.6" height="9" rx="1" fill={C.white} /><rect x="13.1" y="7.5" width="2.6" height="9" rx="1" fill={C.white} /></>);
export const RefreshCw = makeIcon("RefreshCw", () => <><Disc color={C.teal} /><path d="M16.6 10A5 5 0 0 0 7.4 9.2M7.4 14a5 5 0 0 0 9.2.8M16.8 6.4v3.4h-3.4M7.2 17.6v-3.4h3.4" {...W} strokeWidth="2" /></>);
export const RotateCcw = makeIcon("RotateCcw", () => <><Disc color={C.teal} /><path d="M7.5 9.5A5 5 0 1 1 7 13.5M7.3 6.3v3.4h3.4" {...W} strokeWidth="2" /></>);
export const History = makeIcon("History", () => <><Disc color={C.blue} /><path d="M7.2 9.5A5.2 5.2 0 1 1 6.8 13.5M7 6.3v3.4h3.4M12 9.5V12l1.8 1.5" {...W} strokeWidth="2" /></>);
export const Clock3 = makeIcon("Clock3", () => <><Disc color={C.blue} /><path d="M12 6.5V12h4.5" {...W} /></>);
export const Search = makeIcon("Search", () => (
  <>
    <path d="M15.4 17.9l2.5-2.5 4.1 4.1a1.8 1.8 0 0 1-2.5 2.5z" fill={C.slateD} />
    <circle cx="10.5" cy="10.5" r="8" fill={C.blue} />
    <circle cx="10.5" cy="10.5" r="5" fill={C.paper} />
    <path d="M8 8.6a3 3 0 0 1 2.4-1.4" {...line(C.blue, 1.6)} />
  </>
));
export const Filter = makeIcon("Filter", () => (
  <>
    <path d="M3 4.5A1.5 1.5 0 0 1 4.5 3h15a1.5 1.5 0 0 1 1.1 2.5L14.5 12.5V19a1 1 0 0 1-.6.9l-3 1.4a1 1 0 0 1-1.4-.9v-7.9L3.4 5.5A1.5 1.5 0 0 1 3 4.5z" fill={C.amber} />
    <path d="M12 3h7.5a1.5 1.5 0 0 1 1.1 2.5L14.5 12.5V19a1 1 0 0 1-.6.9L12 20.8z" fill={C.amberD} />
  </>
));
export const ListFilter = makeIcon("ListFilter", () => <><Tile color={C.amber} /><path d="M7 8h10M8.8 12h6.4M10.6 16h2.8" {...W} /></>);
export const Download = makeIcon("Download", () => <><Tile color={C.green} /><path d="M12 6.5v7.5M8.5 10.8l3.5 3.5 3.5-3.5M7.5 17.5h9" {...W} /></>);
export const Upload = makeIcon("Upload", () => <><Tile color={C.blue} /><path d="M12 14.5V7M8.5 10.3 12 6.8l3.5 3.5M7.5 17.5h9" {...W} /></>);
export const Ban = makeIcon("Ban", () => <><Disc color={C.coral} /><rect x="6" y="10.5" width="12" height="3" rx="1.5" fill={C.white} /></>);
export const LogOut = makeIcon("LogOut", () => (
  <>
    <rect x="2.5" y="2.5" width="12" height="19" rx="2.5" fill={C.slate} />
    <circle cx="11" cy="12" r="1.1" fill={C.white} />
    <path d="M9.5 12h11M17.2 8.5 20.8 12l-3.6 3.5" {...line(C.coral, 2.6)} />
  </>
));
export const PanelLeftClose = makeIcon("PanelLeftClose", () => (
  <>
    <rect x="2" y="3" width="20" height="18" rx="3.5" fill={C.slate} />
    <path d="M5.5 3H9v18H5.5A3.5 3.5 0 0 1 2 17.5v-11A3.5 3.5 0 0 1 5.5 3z" fill={C.teal} />
    <path d="M16.5 9l-3 3 3 3" {...W} />
  </>
));
export const PanelLeftOpen = makeIcon("PanelLeftOpen", () => (
  <>
    <rect x="2" y="3" width="20" height="18" rx="3.5" fill={C.slate} />
    <path d="M5.5 3H9v18H5.5A3.5 3.5 0 0 1 2 17.5v-11A3.5 3.5 0 0 1 5.5 3z" fill={C.teal} />
    <path d="M13.5 9l3 3-3 3" {...W} />
  </>
));
export const Copy = makeIcon("Copy", () => <><rect x="8" y="2" width="13.5" height="14" rx="2.5" fill={C.blueD} /><rect x="2.5" y="8" width="13.5" height="14" rx="2.5" fill={C.blue} /><path d="M6 13h6.5M6 16.5h4.5" {...W} strokeWidth="1.8" /></>);
export const Link2 = makeIcon("Link2", () => (
  <>
    <rect x="1.5" y="7.5" width="12" height="9" rx="4.5" fill={C.blue} />
    <rect x="10.5" y="7.5" width="12" height="9" rx="4.5" fill={C.teal} />
    <rect x="4.5" y="10.8" width="5" height="2.4" rx="1.2" fill={C.paper} />
    <rect x="14.5" y="10.8" width="5" height="2.4" rx="1.2" fill={C.paper} />
  </>
));

/* ---- status ------------------------------------------------------------- */

const drawAlert = () => <><Disc color={C.coral} /><path d="M12 6.8v6.4" {...W} strokeWidth="2.6" /><circle cx="12" cy="16.8" r="1.5" fill={C.white} /></>;
export const CircleAlert = makeIcon("CircleAlert", drawAlert);
export const AlertTriangle = makeIcon("AlertTriangle", () => (
  <>
    <path d="M10.3 2.9a2 2 0 0 1 3.4 0l8.6 15.2a2 2 0 0 1-1.7 2.9H3.4a2 2 0 0 1-1.7-2.9z" fill={C.amber} />
    <path d="M12 8.6v5.2" {...line(C.navy, 2.5)} />
    <circle cx="12" cy="17.1" r="1.4" fill={C.navy} />
  </>
));
export const Info = makeIcon("Info", () => <><Disc color={C.blue} /><circle cx="12" cy="7.4" r="1.5" fill={C.white} /><path d="M12 11v6.2" {...W} strokeWidth="2.6" /></>);
export const CircleHelp = makeIcon("CircleHelp", () => <><Disc color={C.blue} /><path d="M9.4 9.3a2.7 2.7 0 1 1 3.7 2.5c-.7.3-1.1.9-1.1 1.6v.5" {...W} /><circle cx="12" cy="17.2" r="1.4" fill={C.white} /></>);
export const Target = makeIcon("Target", () => (
  <>
    <circle cx="12" cy="12" r="10.5" fill={C.coral} />
    <circle cx="12" cy="12" r="7.3" fill={C.paper} />
    <circle cx="12" cy="12" r="4.3" fill={C.coral} />
    <circle cx="12" cy="12" r="1.7" fill={C.paper} />
  </>
));
export const Gauge = makeIcon("Gauge", () => (
  <>
    <path d="M3.5 17A8.5 8.5 0 0 1 7.75 9.64" fill="none" stroke={C.green} strokeWidth="4" />
    <path d="M7.75 9.64a8.5 8.5 0 0 1 8.5 0" fill="none" stroke={C.amber} strokeWidth="4" />
    <path d="M16.25 9.64A8.5 8.5 0 0 1 20.5 17" fill="none" stroke={C.coral} strokeWidth="4" />
    <path d="M12 17l4-5" {...line(C.slateD, 2.4)} />
    <circle cx="12" cy="17" r="2.2" fill={C.slateD} />
  </>
));

/* ---- security ------------------------------------------------------------ */

export const ShieldCheck = makeIcon("ShieldCheck", () => <Shield color={C.teal} shade={C.tealD}><path d="M8 12.2l2.8 2.8L16.2 9.5" {...W} strokeWidth="2.4" /></Shield>);
export const ShieldAlert = makeIcon("ShieldAlert", () => <Shield color={C.coral} shade={C.coralD}><path d="M12 7v6" {...W} strokeWidth="2.6" /><circle cx="12" cy="16.4" r="1.5" fill={C.white} /></Shield>);
export const ShieldOff = makeIcon("ShieldOff", () => <Shield color={C.slate} shade={C.slateD}><path d="M8 8l8 8" {...W} strokeWidth="2.4" /></Shield>);
export const ShieldPlus = makeIcon("ShieldPlus", () => <Shield color={C.blue} shade={C.blueD}><path d="M12 7.5v8M8 11.5h8" {...W} strokeWidth="2.4" /></Shield>);
export const KeyRound = makeIcon("KeyRound", () => (
  <>
    <path d="M11.5 12 21 21.5" {...line(C.amberD, 3.4)} />
    <path d="M17 17.5l2.3-2.3M19.6 20.1l1.6-1.6" {...line(C.amberD, 3)} />
    <circle cx="8" cy="8.5" r="6.5" fill={C.amber} />
    <circle cx="6.6" cy="7.1" r="1.9" fill={C.amberD} />
  </>
));
export const LockKeyhole = makeIcon("LockKeyhole", () => (
  <>
    <path d="M7.5 10.5V7.5a4.5 4.5 0 0 1 9 0v3" {...line(C.slate, 2.6)} />
    <rect x="4" y="10" width="16" height="12" rx="2.5" fill={C.amber} />
    <circle cx="12" cy="15" r="1.8" fill={C.navy} />
    <rect x="11.2" y="15" width="1.6" height="3.6" rx=".8" fill={C.navy} />
  </>
));
export const Fingerprint = makeIcon("Fingerprint", () => (
  <>
    <Disc color={C.teal} />
    <path d="M8.3 16c.5-1.1.8-2.4.8-3.9a2.9 2.9 0 0 1 5.8 0c0 2.1-.4 4-1.2 5.7M12 12.2c0 2.3-.5 4.4-1.5 6.1M6.4 10.4a5.8 5.8 0 0 1 10.9-1.7M17.7 12.4c0 1.1-.1 2.2-.4 3.2" {...W} strokeWidth="1.6" />
  </>
));
export const Radio = makeIcon("Radio", () => (
  <>
    <path d="M8.2 15.8a5.4 5.4 0 0 1 0-7.6M15.8 8.2a5.4 5.4 0 0 1 0 7.6M5 19a9.9 9.9 0 0 1 0-14M19 5a9.9 9.9 0 0 1 0 14" {...line(C.teal, 2.2)} />
    <circle cx="12" cy="12" r="2.6" fill={C.coral} />
  </>
));
export const RadioTower = makeIcon("RadioTower", () => (
  <>
    <path d="M12 10 7.2 22h9.6z" fill={C.slate} />
    <path d="M7.9 11.6a5.4 5.4 0 0 1 0-7.6M16.1 4a5.4 5.4 0 0 1 0 7.6" {...line(C.teal, 2.2)} />
    <circle cx="12" cy="7.8" r="2.4" fill={C.coral} />
  </>
));
export const Network = makeIcon("Network", () => (
  <>
    <path d="M12 8v4.5M5.5 15.5v-3h13v3" {...line(C.slate, 2)} />
    <rect x="8.5" y="2" width="7" height="6" rx="1.6" fill={C.blue} />
    <rect x="2" y="15.5" width="7" height="6.5" rx="1.6" fill={C.teal} />
    <rect x="15" y="15.5" width="7" height="6.5" rx="1.6" fill={C.amber} />
  </>
));
export const Database = makeIcon("Database", () => (
  <>
    <path d="M3.5 5v14c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3V5z" fill={C.blue} />
    <path d="M3.5 9.8c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3M3.5 14.6c0 1.7 3.8 3 8.5 3s8.5-1.3 8.5-3" {...line(C.blueD, 1.7)} />
    <ellipse cx="12" cy="5" rx="8.5" ry="3" fill={C.blueD} />
  </>
));
export const Activity = makeIcon("Activity", () => <><Tile color={C.teal} /><path d="M5 12.5h3l2-5 3.5 9 2-4H19" {...W} strokeWidth="2" /></>);
export const HeartPulse = makeIcon("HeartPulse", () => (
  <>
    <path d="M12 21s-8.5-5.2-8.5-11.2A4.8 4.8 0 0 1 12 6.6a4.8 4.8 0 0 1 8.5 3.2C20.5 15.8 12 21 12 21z" fill={C.coral} />
    <path d="M5.5 12.2h3l1.5-2.5 2.5 5 1.5-2.5h4.5" {...W} strokeWidth="1.7" />
  </>
));
export const Zap = makeIcon("Zap", () => <><path d="M13.5 1.5 4 13.5h7l-1.5 9L20 10h-7z" fill={C.amber} /><path d="M13.5 1.5 12.4 10H20L9.5 22.5 11 13.5z" fill={C.amberD} opacity=".55" /></>);
export const BrainCircuit = makeIcon("BrainCircuit", () => (
  <>
    <path d="M11.3 3.6A3.4 3.4 0 0 0 7.6 6a3.4 3.4 0 0 0-3 4 3.4 3.4 0 0 0 .5 5.4A3.4 3.4 0 0 0 8 20.3a3 3 0 0 0 3.3-1z" fill={C.coral} />
    <path d="M12.7 3.6A3.4 3.4 0 0 1 16.4 6a3.4 3.4 0 0 1 3 4 3.4 3.4 0 0 1-.5 5.4 3.4 3.4 0 0 1-2.9 4.9 3 3 0 0 1-3.3-1z" fill={C.coralD} />
    <path d="M8.2 9h1.6M7.6 13h2.2M15 8.5v2.2l1.6 1.2M15.5 16.2v-2" {...W} strokeWidth="1.5" />
  </>
));
export const Bot = makeIcon("Bot", () => (
  <>
    <path d="M12 2.8V6" {...line(C.amberD, 2)} />
    <circle cx="12" cy="2.6" r="1.7" fill={C.amber} />
    <rect x="3.5" y="6" width="17" height="14" rx="4" fill={C.blue} />
    <rect x="6" y="9" width="12" height="7" rx="3" fill={C.navy} />
    <circle cx="9.5" cy="12.5" r="1.5" fill={C.teal} />
    <circle cx="14.5" cy="12.5" r="1.5" fill={C.teal} />
  </>
));
export const Sparkles = makeIcon("Sparkles", () => (
  <>
    <path d="M10 2.5l1.9 5.4L17.3 10l-5.4 1.9L10 17.3l-1.9-5.4L2.7 10l5.4-1.9z" fill={C.amber} />
    <path d="M18 13.5l1 2.4 2.4 1-2.4 1-1 2.4-1-2.4-2.4-1 2.4-1z" fill={C.teal} />
  </>
));

/* ---- people and settings ------------------------------------------------- */

export const UserRound = makeIcon("UserRound", () => <Person head={C.blue} body={C.blueD} />);
const drawUsers = () => (
  <>
    <Person head={C.tealD} body={C.teal} x={4} scale={0.78} />
    <Person head={C.blue} body={C.blueD} x={-3} scale={0.86} />
  </>
);
export const Users = makeIcon("Users", drawUsers);
export const UsersRound = makeIcon("UsersRound", drawUsers);
export const UserPlus = makeIcon("UserPlus", () => <><Person head={C.blue} body={C.blueD} x={-2.5} scale={0.88} /><Badge color={C.green} glyph="plus" cx={18} cy={7.5} /></>);
export const UserRoundCog = makeIcon("UserRoundCog", () => <><Person head={C.blue} body={C.blueD} x={-2.5} scale={0.88} /><Badge color={C.slate} glyph="gear" /></>);
export const Settings = makeIcon("Settings", () => <GearShape color={C.slate} hub={C.paper} />);
export const Building2 = makeIcon("Building2", () => (
  <>
    <rect x="15" y="9" width="6" height="13" rx="1.2" fill={C.blueD} />
    <rect x="3.5" y="2" width="12" height="20" rx="1.6" fill={C.blue} />
    {[5, 9, 13].map((y) => [6.2, 10.6].map((x) => <rect key={`${x}-${y}`} x={x} y={y} width="2.2" height="2.2" rx=".4" fill={C.white} />))}
    <rect x="8.4" y="17.5" width="2.4" height="4.5" fill={C.navy} />
  </>
));
export const Headphones = makeIcon("Headphones", () => (
  <>
    <path d="M3.5 15v-3a8.5 8.5 0 0 1 17 0v3" {...line(C.slate, 2.4)} />
    <rect x="2.5" y="13.5" width="5.5" height="8" rx="2" fill={C.teal} />
    <rect x="16" y="13.5" width="5.5" height="8" rx="2" fill={C.teal} />
  </>
));
export const Smartphone = makeIcon("Smartphone", () => (
  <>
    <rect x="5.5" y="1.5" width="13" height="21" rx="3" fill={C.blueD} />
    <rect x="7.5" y="4" width="9" height="13.5" rx="1" fill={C.paper} />
    <circle cx="12" cy="20" r="1.1" fill={C.paper} />
  </>
));
export const Keyboard = makeIcon("Keyboard", () => (
  <>
    <rect x="1.5" y="5" width="21" height="14" rx="2.5" fill={C.slate} />
    {[4.5, 8, 11.5, 15, 18.5].map((x) => <rect key={`a${x}`} x={x - 1} y="8" width="2" height="2" rx=".4" fill={C.white} />)}
    {[6.2, 9.8, 13.4, 17].map((x) => <rect key={`b${x}`} x={x - 1} y="11.4" width="2" height="2" rx=".4" fill={C.white} />)}
    <rect x="7" y="15" width="10" height="1.8" rx=".6" fill={C.white} />
  </>
));
export const Palette = makeIcon("Palette", () => (
  <>
    <path d="M12 2.5c5.5 0 9.5 3.8 9.5 8.3 0 3-2.3 4.7-4.6 4.7h-1.7a1.7 1.7 0 0 0-1.3 2.8 1.7 1.7 0 0 1-1.3 2.9C6.9 21.2 2.5 17 2.5 12S6.5 2.5 12 2.5z" fill={C.amber} />
    <circle cx="7.3" cy="11.5" r="1.7" fill={C.coral} />
    <circle cx="9.8" cy="7" r="1.7" fill={C.teal} />
    <circle cx="14.8" cy="7" r="1.7" fill={C.blue} />
    <circle cx="17.6" cy="11" r="1.7" fill={C.green} />
  </>
));
export const Sun = makeIcon("Sun", () => (
  <>
    {Array.from({ length: 8 }, (_, index) => (
      <rect key={index} x="11" y="1" width="2" height="3.6" rx="1" fill={C.amberD} transform={`rotate(${index * 45} 12 12)`} />
    ))}
    <circle cx="12" cy="12" r="5.6" fill={C.amber} />
  </>
));
export const Moon = makeIcon("Moon", () => <path d="M20.5 14.5A8.5 8.5 0 0 1 9.5 3.5a8.5 8.5 0 1 0 11 11z" fill={C.amber} />);
// Password show/hide toggles: plain outlines in the text colour, no fill.
const EYE_OUTLINE = "M2 12s3.6-6.5 10-6.5S22 12 22 12s-3.6 6.5-10 6.5S2 12 2 12z";
export const Eye = makeIcon("Eye", () => (
  <>
    <path d={EYE_OUTLINE} {...line("currentColor", 1.8)} />
    <circle cx="12" cy="12" r="3" {...line("currentColor", 1.8)} />
  </>
));
export const EyeOff = makeIcon("EyeOff", () => (
  <>
    <path d={EYE_OUTLINE} {...line("currentColor", 1.8)} />
    <circle cx="12" cy="12" r="3" {...line("currentColor", 1.8)} />
    <path d="M4 4l16 16" {...line("currentColor", 1.8)} />
  </>
));

/* ---- communication ------------------------------------------------------- */

export const Mail = makeIcon("Mail", () => <Envelope />);
export const MailCheck = makeIcon("MailCheck", () => <><Envelope /><Badge color={C.green} glyph="check" /></>);
export const MailOpen = makeIcon("MailOpen", () => (
  <>
    <path d="M2 10 12 3l10 7v10a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2z" fill={C.blueD} />
    <rect x="5" y="6" width="14" height="10" rx="1" fill={C.paper} />
    <path d="M7.5 9h9M7.5 12h6" {...line(C.blue, 1.6)} />
    <path d="M2 10.5 12 17l10-6.5V20a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2z" fill={C.blue} />
  </>
));
export const Send = makeIcon("Send", () => (
  <>
    <path d="M21.5 2.5 2.8 10.2c-.9.4-.8 1.6.1 1.9l6.4 2.1 2.1 6.4c.3.9 1.5 1 1.9.1z" fill={C.teal} />
    <path d="M21.5 2.5 9.3 14.2l2.1 6.4c.3.9 1.5 1 1.9.1z" fill={C.tealD} />
  </>
));
export const MessageSquareText = makeIcon("MessageSquareText", () => (
  <>
    <path d="M4 3h16a2 2 0 0 1 2 2v11a2 2 0 0 1-2 2H9.5L4 22v-4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2z" fill={C.blue} />
    <path d="M7 8.5h10M7 12.5h6" {...W} />
  </>
));
export const Bell = makeIcon("Bell", () => <><path d={BELL} fill={C.amber} /><circle cx="12" cy="19.6" r="2.4" fill={C.amberD} /></>);
export const BellRing = makeIcon("BellRing", () => (
  <>
    <path d="M2.5 7.5A9 9 0 0 1 4.9 3M21.5 7.5A9 9 0 0 0 19.1 3" {...line(C.coral, 2)} />
    <path d={BELL} fill={C.amber} />
    <circle cx="12" cy="19.6" r="2.4" fill={C.amberD} />
  </>
));

/* ---- files and records --------------------------------------------------- */

export const FileText = makeIcon("FileText", () => <Page />);
export const ScrollText = makeIcon("ScrollText", () => <Page lines={C.teal} />);
export const FileUp = makeIcon("FileUp", () => <><Page lines={C.paperD} /><Badge color={C.blue} glyph="up" /></>);
export const FileClock = makeIcon("FileClock", () => <><Page lines={C.paperD} /><Badge color={C.amber} glyph="clock" /></>);
export const FileSearch = makeIcon("FileSearch", () => <><Page lines={C.paperD} /><Badge color={C.blue} glyph="search" /></>);
export const FilePlus2 = makeIcon("FilePlus2", () => <><Page lines={C.paperD} /><Badge color={C.green} glyph="plus" /></>);
export const FileCode2 = makeIcon("FileCode2", () => <><Page lines={C.paperD} /><Badge color={C.teal} glyph="code" /></>);
export const FileBarChart = makeIcon("FileBarChart", () => (
  <>
    <Page lines={null} />
    <rect x="7.3" y="14" width="2.6" height="5.5" rx=".5" fill={C.teal} />
    <rect x="10.9" y="10.5" width="2.6" height="9" rx=".5" fill={C.blue} />
    <rect x="14.5" y="12.5" width="2.6" height="7" rx=".5" fill={C.coral} />
  </>
));
export const Files = makeIcon("Files", () => (
  <>
    <rect x="8.5" y="1.5" width="12.5" height="16" rx="1.8" fill={C.blue} />
    <rect x="3" y="6" width="12.5" height="16.5" rx="1.8" fill={C.paper} />
    <path d="M6 11h6.5M6 14.5h6.5M6 18h4" {...line(C.blue, 1.7)} />
  </>
));
const BOOK_LEFT = "M2 5.5c3.1-1.3 6.3-1.2 9.3.7v14.6c-3-1.9-6.2-2-9.3-.7z";
const BOOK_RIGHT = "M22 5.5c-3.1-1.3-6.3-1.2-9.3.7v14.6c3-1.9 6.2-2 9.3-.7z";
export const BookOpen = makeIcon("BookOpen", () => <><path d={BOOK_LEFT} fill={C.blue} /><path d={BOOK_RIGHT} fill={C.blueD} /></>);
export const BookOpenCheck = makeIcon("BookOpenCheck", () => <><path d={BOOK_LEFT} fill={C.blue} /><path d={BOOK_RIGHT} fill={C.blueD} /><Badge color={C.green} glyph="check" cx={18} cy={6.5} /></>);
export const StickyNote = makeIcon("StickyNote", () => (
  <>
    <path d="M4 3h16a1 1 0 0 1 1 1v11l-6 6H4a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1z" fill={C.amber} />
    <path d="M21 15h-5a1 1 0 0 0-1 1v5z" fill={C.amberD} />
    <path d="M7 8h10M7 11.5h7" {...line(C.amberD, 1.8)} />
  </>
));
export const CalendarDays = makeIcon("CalendarDays", () => (
  <>
    <rect x="2.5" y="4" width="19" height="17.5" rx="2.5" fill={C.paper} />
    <path d="M5 4h14a2.5 2.5 0 0 1 2.5 2.5v3h-19v-3A2.5 2.5 0 0 1 5 4z" fill={C.coral} />
    <rect x="6.8" y="2" width="2.2" height="4.5" rx="1.1" fill={C.slateD} />
    <rect x="15" y="2" width="2.2" height="4.5" rx="1.1" fill={C.slateD} />
    {[[6, 12], [10.8, 12], [15.6, 12], [6, 16.4], [10.8, 16.4]].map(([x, y]) => <rect key={`${x}-${y}`} x={x} y={y} width="2.4" height="2.4" rx=".5" fill={C.blue} />)}
    <rect x="15.6" y="16.4" width="2.4" height="2.4" rx=".5" fill={C.coral} />
  </>
));
export const ListChecks = makeIcon("ListChecks", () => (
  <>
    <path d="M3 6.5l1.8 1.8L8 5M3 15.5l1.8 1.8L8 14" {...line(C.green, 2.4)} />
    <rect x="11" y="5.3" width="10" height="2.6" rx="1.3" fill={C.slate} />
    <rect x="11" y="14.3" width="10" height="2.6" rx="1.3" fill={C.slate} />
  </>
));
export const Archive = makeIcon("Archive", () => (
  <>
    <path d="M3.5 8.5h17V19a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z" fill={C.amber} />
    <rect x="2" y="3" width="20" height="5.5" rx="1.5" fill={C.amberD} />
    <rect x="9" y="11.5" width="6" height="2.3" rx="1.15" fill={C.white} />
  </>
));
export const Save = makeIcon("Save", () => (
  <>
    <path d="M4.5 2.5h12l4 4v13a2 2 0 0 1-2 2h-14a2 2 0 0 1-2-2v-15a2 2 0 0 1 2-2z" fill={C.blue} />
    <rect x="7" y="2.5" width="8.5" height="5.5" rx=".8" fill={C.blueD} />
    <rect x="6.5" y="12.5" width="11" height="9" rx="1" fill={C.paper} />
  </>
));
export const Trash2 = makeIcon("Trash2", () => (
  <>
    <rect x="9" y="1.8" width="6" height="3.2" rx="1" fill={C.coralD} />
    <rect x="3.5" y="4.4" width="17" height="3.2" rx="1.6" fill={C.coralD} />
    <path d="M5.5 8.6h13l-1 12a1.5 1.5 0 0 1-1.5 1.4H8a1.5 1.5 0 0 1-1.5-1.4z" fill={C.coral} />
    <rect x="9.2" y="11" width="1.7" height="7.5" rx=".85" fill={C.white} />
    <rect x="13.1" y="11" width="1.7" height="7.5" rx=".85" fill={C.white} />
  </>
));
export const Pencil = makeIcon("Pencil", () => (
  <>
    <path d="M15.2 3.6a2 2 0 0 1 2.8 0l2.4 2.4a2 2 0 0 1 0 2.8L9.2 20H4v-5.2z" fill={C.amber} />
    <path d="M15.2 3.6a2 2 0 0 1 2.8 0l2.4 2.4a2 2 0 0 1 0 2.8l-1.6 1.6-5.2-5.2z" fill={C.coral} />
    <path d="M4 14.8 9.2 20H4z" fill={C.paper} />
    <path d="M4 17.6V20h2.4z" fill={C.navy} />
  </>
));
// Pinned notes pass fill="currentColor"; unpinned ones pass fill="none" and
// get a muted pin so the two states stay distinguishable.
export const Pin = makeIcon("Pin", ({ fill }) => {
  const muted = fill === "none";
  return (
    <>
      <path d="M12 14.5v7.5" {...line(C.slateD, 2.2)} />
      <path d="M8 2.5h8l-1.1 6 3.1 3.6v2.4H6v-2.4l3.1-3.6z" fill={muted ? C.slate : C.coral} />
      <path d="M12 2.5h4l-1.1 6 3.1 3.6v2.4H12z" fill={muted ? C.slateD : C.coralD} />
    </>
  );
});
export const Workflow = makeIcon("Workflow", () => (
  <>
    <path d="M6 9.5v6.5a1.5 1.5 0 0 0 1.5 1.5H14" {...line(C.slate, 2)} />
    <rect x="2" y="2.5" width="8" height="7" rx="2" fill={C.teal} />
    <rect x="14" y="14" width="8" height="7" rx="2" fill={C.amber} />
  </>
));
export const GitBranch = makeIcon("GitBranch", () => (
  <>
    <path d="M6.5 6v12M17.5 9c0 4.2-4.5 5.2-11 6.5" {...line(C.slate, 2)} />
    <circle cx="6.5" cy="5" r="2.8" fill={C.teal} />
    <circle cx="6.5" cy="19" r="2.8" fill={C.teal} />
    <circle cx="17.5" cy="6.5" r="2.8" fill={C.coral} />
  </>
));
