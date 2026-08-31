import type { ReactNode } from "react";
import { cn } from "@/lib/utils";
import { AnimatedText } from "./AnimatedText";

type SecondaryButtonProps = {
  children: ReactNode;
  href: string;
  size?: "sm";
  className?: string;
};

const sizeClassMap: Record<NonNullable<SecondaryButtonProps["size"]>, string> = {
  sm: "h-8 px-4 text-sm",
};

export function SecondaryButton({ children, href, size = "sm", className }: SecondaryButtonProps) {
  return (
    <a
      href={href}
      className={cn(
        "group inline-flex items-center justify-center rounded-full font-inter leading-none font-medium transition-colors",
        "bg-landing-surface hover:bg-landing-surface-hover border border-landing-border text-foreground backdrop-blur-[2.5px]",
        sizeClassMap[size],
        className
      )}
    >
      <AnimatedText>{children}</AnimatedText>
    </a>
  );
}
