import { cn } from "@/lib/utils";

type MIconProps = {
  name: string;
  size?: number;
  weight?: number;
  fill?: number;
  grade?: number;
  opticalSize?: number;
  className?: string;
};

export function MIcon({
  name,
  size = 20,
  weight = 400,
  fill = 0,
  grade = 0,
  opticalSize = 24,
  className,
}: MIconProps) {
  return (
    <span
      className={cn("material-symbols-outlined select-none leading-none", className)}
      style={{
        fontSize: size,
        fontVariationSettings: `'FILL' ${fill}, 'wght' ${weight}, 'GRAD' ${grade}, 'opsz' ${opticalSize}`,
      }}
    >
      {name}
    </span>
  );
}
