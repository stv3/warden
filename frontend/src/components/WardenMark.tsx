/**
 * Warden brand mark.
 *
 * Three equal arc strokes arranged at 120° intervals on a shared circle —
 * the same radial-symmetry language used by Anthropic and OpenAI.
 *
 * The three arcs reference the warden concept: watching simultaneously in
 * every direction.  At a glance it reads as a clean geometric spinner;
 * zoom in and the three distinct strokes give it character without being
 * decorative or illustrative.
 *
 * Geometry (viewBox 0 0 32 32, radius 10, center 16 16):
 *   Each arc spans 70°, centred at 270° / 30° / 150° (12, 4, 8 o'clock).
 *   stroke="currentColor" so the mark inherits text colour from its container.
 */
export function WardenMark({
  size = 20,
  className = '',
}: {
  size?: number;
  className?: string;
}) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 32 32"
      fill="none"
      aria-hidden="true"
      className={className}
    >
      {/* 12 o'clock  —  235° → 305° */}
      <path
        d="M 10.26 7.81 A 10 10 0 0 1 21.74 7.81"
        stroke="currentColor"
        strokeWidth="3.5"
        strokeLinecap="round"
      />
      {/* 4 o'clock   —  355° → 65°  */}
      <path
        d="M 25.96 15.13 A 10 10 0 0 1 20.23 25.06"
        stroke="currentColor"
        strokeWidth="3.5"
        strokeLinecap="round"
      />
      {/* 8 o'clock   —  115° → 185° */}
      <path
        d="M 11.77 25.06 A 10 10 0 0 1 6.04 16.87"
        stroke="currentColor"
        strokeWidth="3.5"
        strokeLinecap="round"
      />
    </svg>
  );
}
