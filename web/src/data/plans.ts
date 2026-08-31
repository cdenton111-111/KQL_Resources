export type Feature = { text: string; included: boolean };

export type Plan = {
  name: string;
  price: string;
  originalPrice?: string;
  description: string;
  features: Feature[];
  featured?: boolean;
  badge?: string;
  bg: string;
};

export const plans: Plan[] = [
  {
    name: "Standard",
    price: "999",
    description: "A polished site, built for you.",
    bg: "#161616",
    features: [
      { text: "Custom website design", included: true },
      { text: "Up to 5 pages", included: true },
      { text: "Mobile responsive layout", included: true },
      { text: "SEO optimization", included: false },
      { text: "Priority support", included: false },
    ],
  },
  {
    name: "Premium",
    price: "1299",
    description: "Everything in Standard, plus more.",
    bg: "#252525",
    features: [
      { text: "Custom website design", included: true },
      { text: "Up to 5 pages", included: true },
      { text: "Mobile responsive layout", included: true },
      { text: "SEO optimization", included: true },
      { text: "Priority support", included: true },
    ],
    featured: true,
    badge: "Best Value",
  },
];
