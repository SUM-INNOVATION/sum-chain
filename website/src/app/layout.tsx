import type { Metadata } from "next";
import { Inter, Space_Grotesk, JetBrains_Mono } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
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
  title: "SUM Chain | A Utility-Backed Layer-1",
  description:
    "SUM Chain is a high-performance Layer-1 blockchain, built entirely in Rust, powering Koppa (Ϙ). Value backed by real on-chain utility: decentralized storage, verifiable AI compute, encrypted messaging, and document credentials.",
  keywords: ["blockchain", "cryptocurrency", "Koppa", "SUM Chain", "Layer 1", "Rust", "decentralized"],
  openGraph: {
    title: "SUM Chain | A Utility-Backed Layer-1",
    description:
      "High-performance Layer-1 blockchain, built in Rust, powering Koppa (Ϙ). Storage, verifiable AI, messaging, and credentials on-chain.",
    url: "https://sumchain.io",
    siteName: "SUM Chain",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "SUM Chain | A Utility-Backed Layer-1",
    description: "High-performance Layer-1 blockchain, built in Rust, powering Koppa (Ϙ).",
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
        className={`${inter.variable} ${spaceGrotesk.variable} ${jetbrainsMono.variable} antialiased bg-background text-foreground`}
      >
        <div className="noise-overlay" aria-hidden="true" />
        {children}
      </body>
    </html>
  );
}
