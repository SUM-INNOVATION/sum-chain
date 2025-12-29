import type { Metadata } from "next";
import { Inter, Space_Grotesk } from "next/font/google";
import "./globals.css";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
});

const spaceGrotesk = Space_Grotesk({
  variable: "--font-space-grotesk",
  subsets: ["latin"],
});

export const metadata: Metadata = {
  title: "SUM Chain | The Future of Digital Currency",
  description: "SUM Chain is a high-performance Layer-1 blockchain with Koppa (Ϙ) - the native currency designed for global peer-to-peer transactions. Fast, secure, and built entirely in Rust.",
  keywords: ["blockchain", "cryptocurrency", "Koppa", "SUM Chain", "Layer 1", "Rust", "decentralized"],
  openGraph: {
    title: "SUM Chain | The Future of Digital Currency",
    description: "High-performance Layer-1 blockchain with Koppa (Ϙ) currency. Fast, secure, and built entirely in Rust.",
    url: "https://sum-chain.xyz",
    siteName: "SUM Chain",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "SUM Chain | The Future of Digital Currency",
    description: "High-performance Layer-1 blockchain with Koppa (Ϙ) currency.",
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
        className={`${inter.variable} ${spaceGrotesk.variable} antialiased bg-[#0a0a0a] text-white`}
      >
        {children}
      </body>
    </html>
  );
}
