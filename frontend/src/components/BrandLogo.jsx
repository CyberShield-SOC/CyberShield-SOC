/**
 * Shared CyberShield mark. The image remains decorative when the adjacent
 * wordmark supplies the accessible brand name.
 */
export function BrandLogo({ size = "default", className = "" }) {
  return (
    <span
      className={`cybershield-logo ${className}`.trim()}
      data-size={size}
      aria-hidden="true"
    >
      <img src="/assets/CYBERSHIELD_shield.jpg" alt="" loading="eager" />
    </span>
  );
}
