import { FadeUp } from "@/components/ui/FadeUp";
import { PricingCard } from "@/components/PricingCard";
import { plans } from "@/data/plans";

export default function PricingSection() {
  return (
    <section id="pricing" className="relative w-full bg-background py-12 sm:py-16">
      <div className="mx-auto max-w-[1080px] px-4 sm:px-6">
        <div className="mb-14 flex flex-col items-start gap-10 lg:flex-row lg:items-end lg:justify-between">
          <div className="max-w-2xl">
            <FadeUp>
              <span className="mb-6 inline-flex items-center gap-2 rounded-full bg-landing-surface border border-white/10 px-3 py-1 text-xs text-foreground/80 backdrop-blur">
                <span className="h-1.5 w-1.5 rounded-full bg-foreground/70" />
                Pricing
              </span>
            </FadeUp>
            <FadeUp delay={0.1}>
              <h2 className="text-3xl sm:text-4xl font-normal tracking-[-0.02em] leading-[1.05] text-foreground">
                Clear pricing plans
                <br className="hidden sm:block" /> that scale with you.
              </h2>
            </FadeUp>
          </div>
          <FadeUp delay={0.2}>
            <p className="max-w-sm text-sm sm:text-base text-foreground/60">
              One-time payment. No hidden fees. Pick the plan that fits your website.
            </p>
          </FadeUp>
        </div>

        <div className="mx-auto grid max-w-3xl grid-cols-1 gap-6 md:grid-cols-2">
          {plans.map((p) => (
            <PricingCard key={p.name} plan={p} />
          ))}
        </div>
      </div>
    </section>
  );
}
