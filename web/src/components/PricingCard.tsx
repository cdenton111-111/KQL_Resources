import { cn } from "@/lib/utils";
import type { Plan } from "@/data/plans";
import { SpotlightBorder } from "@/components/ui/SpotlightBorder";
import { FadeUp } from "@/components/ui/FadeUp";
import { MIcon } from "@/components/ui/MIcon";
import { PrimaryButton } from "@/components/ui/PrimaryButton";
import { SecondaryButton } from "@/components/ui/SecondaryButton";

type PricingCardProps = {
  plan: Plan;
};

export function PricingCard({ plan }: PricingCardProps) {
  return (
    <SpotlightBorder radius="2xl" size={460} intensity={0.5} className="relative h-full p-2 sm:p-3">
      <div
        className="relative flex h-full flex-col rounded-2xl border border-white/10 p-7 sm:p-8"
        style={{ backgroundColor: plan.bg }}
      >
        {plan.badge && (
          <div className="absolute -top-3 left-1/2 -translate-x-1/2 rounded-full border border-white/15 bg-white px-3 py-1 text-xs font-medium text-black">
            {plan.badge}
          </div>
        )}

        <FadeUp delay={0}>
          <div className="text-[11px] uppercase tracking-[0.2em] text-foreground/60">{plan.name}</div>
        </FadeUp>
        <div className="mt-3 border-t border-white/10" />

        <FadeUp delay={0.1}>
          <div className="mt-10 flex items-baseline gap-2">
            <span className="text-[2.75rem] leading-none font-normal tracking-tight text-foreground">
              ${plan.price}
            </span>
            {plan.originalPrice && (
              <span className="text-lg text-foreground/40 line-through">${plan.originalPrice}</span>
            )}
          </div>
        </FadeUp>

        <FadeUp delay={0.2}>
          <p className="mt-4 text-sm leading-relaxed text-foreground/60">{plan.description}</p>
        </FadeUp>

        <FadeUp delay={0.3}>
          <div className="mt-7">
            {plan.featured ? (
              <PrimaryButton href="/auth?mode=signup" size="sm">
                Get Started
              </PrimaryButton>
            ) : (
              <SecondaryButton href="/auth?mode=signup" size="sm">
                Get Started
              </SecondaryButton>
            )}
          </div>
        </FadeUp>

        <FadeUp delay={0.4}>
          <ul className="mt-7 flex flex-1 flex-col gap-2">
            {plan.features.map((f, i) => (
              <li
                key={f.text}
                className={cn(
                  "flex items-center gap-3 py-4 text-sm",
                  i !== 0 && "border-t border-white/10",
                  f.included ? "text-foreground/85" : "text-foreground/40"
                )}
              >
                <span
                  className={cn(
                    "flex h-5 w-5 flex-shrink-0 items-center justify-center rounded-full border",
                    f.included ? "border-white/20 bg-white/[0.06]" : "border-white/10 bg-transparent"
                  )}
                >
                  {f.included ? (
                    <MIcon name="check" size={12} className="text-foreground" />
                  ) : (
                    <MIcon name="close" size={12} className="text-foreground/50" />
                  )}
                </span>
                {f.text}
              </li>
            ))}
          </ul>
        </FadeUp>
      </div>
    </SpotlightBorder>
  );
}
