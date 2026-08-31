import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { AnimatedText } from "./AnimatedText";

type PrimaryButtonProps = {
  children: ReactNode;
  href: string;
  size?: "sm";
  className?: string;
};

const sizeClassMap: Record<NonNullable<PrimaryButtonProps["size"]>, string> = {
  sm: "h-8 px-4 text-sm",
};

export function PrimaryButton({ children, href, size = "sm", className }: PrimaryButtonProps) {
  return (
    <a
      href={href}
      className={cn(
        "group inline-flex items-center justify-center rounded-full font-inter leading-none transition-colors",
        "bg-white/80 hover:bg-white text-black",
        sizeClassMap[size],
        className
      )}
    >
      <AnimatedText>{children}</AnimatedText>
    </a>
  );
}
