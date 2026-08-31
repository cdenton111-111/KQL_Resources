import { useRef, type ReactNode, type PointerEvent as ReactPointerEvent } from "react";
import { cn } from "@/lib/utils";

type SpotlightBorderProps = {
  children: ReactNode;
  className?: string;
  radius?: string;
  size?: number;
  intensity?: number;
};

const radiusClassMap: Record<string, string> = {
  lg: "rounded-lg",
  xl: "rounded-xl",
  "2xl": "rounded-2xl",
  "3xl": "rounded-3xl",
};

export function SpotlightBorder({
  children,
  className,
  radius = "2xl",
  size = 520,
  intensity = 0.5,
}: SpotlightBorderProps) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const radiusClass = radiusClassMap[radius] ?? "rounded-2xl";

  const handlePointerMove = (e: ReactPointerEvent<HTMLDivElement>) => {
    const el = wrapperRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    el.style.setProperty("--spot-x", `${e.clientX - rect.left}px`);
    el.style.setProperty("--spot-y", `${e.clientY - rect.top}px`);
  };

  const handlePointerLeave = () => {
    const el = wrapperRef.current;
    if (!el) return;
    el.style.setProperty("--spot-x", "-9999px");
    el.style.setProperty("--spot-y", "-9999px");
  };

  const spotStyle = {
    background: `radial-gradient(circle var(--size) at var(--spot-x) var(--spot-y), rgba(255,255,255, var(--intensity)), transparent 60%)`,
  };

  return (
    <div
      ref={wrapperRef}
      onPointerMove={handlePointerMove}
      onPointerLeave={handlePointerLeave}
      className={cn("group relative", radiusClass, className)}
      style={
        {
          "--spot-x": "-9999px",
          "--spot-y": "-9999px",
          "--size": `${size}px`,
          "--intensity": intensity,
        } as React.CSSProperties
      }
    >
      <div className={cn("pointer-events-none absolute inset-0 border border-white/10", radiusClass)} />

      <div
        aria-hidden
        className={cn("pointer-events-none absolute inset-0", radiusClass)}
        style={{
          ...spotStyle,
          padding: 1,
          WebkitMask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
          mask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
          WebkitMaskComposite: "xor",
          maskComposite: "exclude",
        }}
      />

      <div
        aria-hidden
        className={cn(
          "pointer-events-none absolute inset-0 opacity-0 transition-opacity duration-300 group-hover:opacity-100",
          radiusClass
        )}
        style={{
          ...spotStyle,
          padding: 1,
          WebkitMask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
          mask: "linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0)",
          WebkitMaskComposite: "xor",
          maskComposite: "exclude",
          filter: "brightness(1.6)",
        }}
      />

      <div className="pointer-events-auto relative">{children}</div>
    </div>
  );
}
