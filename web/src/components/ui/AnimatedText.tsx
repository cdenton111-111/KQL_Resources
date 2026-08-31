import type { ReactNode } from "react";

type AnimatedTextProps = {
  children: ReactNode;
};

export function AnimatedText({ children }: AnimatedTextProps) {
  return (
    <span className="relative inline-block overflow-hidden leading-none">
      <span className="block transition-transform duration-300 ease-[cubic-bezier(0.22,1,0.36,1)] group-hover:-translate-y-full">
        {children}
      </span>
      <span className="absolute left-0 top-full block transition-transform duration-300 ease-[cubic-bezier(0.22,1,0.36,1)] group-hover:-translate-y-full">
        {children}
      </span>
    </span>
  );
}
