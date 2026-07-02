import type { Metadata } from "next";
import { Sora, Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const sora = Sora({
  variable: "--font-sora",
  subsets: ["latin"],
  display: "swap",
});

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
  display: "swap",
});

const jetbrainsMono = JetBrains_Mono({
  variable: "--font-jetbrains-mono",
  subsets: ["latin"],
  display: "swap",
});

export const metadata: Metadata = {
  metadataBase: new URL("https://sumchain.io"),
  title: "SUM Chain | Open Infrastructure for Storage, AI Compute & Governance",
  description:
    "SUM Chain is a Rust-built Layer-1 where Koppa (Ϙ) is backed by real on-chain utility: decentralized storage with Proof-of-Retrievability, verifiable AI compute via OmniNode inference attestations, and code-backed on-chain governance.",
  keywords: [
    "blockchain",
    "Koppa",
    "SUM Chain",
    "Layer 1",
    "Rust",
    "decentralized storage",
    "Proof of Retrievability",
    "AI compute",
    "inference attestation",
    "governance",
  ],
  openGraph: {
    title: "SUM Chain | Open Infrastructure for Storage, AI Compute & Governance",
    description:
      "A Rust-built Layer-1 powering Koppa (Ϙ): decentralized storage, verifiable AI compute, and on-chain governance.",
    url: "https://sumchain.io",
    siteName: "SUM Chain",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "SUM Chain",
    description: "A Rust-built Layer-1 powering Koppa (Ϙ): storage, verifiable AI compute, and governance.",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body
        className={`${sora.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable} antialiased bg-background text-foreground`}
      >
        <div className="noise-overlay" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}
