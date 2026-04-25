'use client';

import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import Link from 'next/link';

type NavLink = {
  name: string;
  href: string;
  external?: boolean;
  comingSoon?: boolean;
};

const navLinks: NavLink[] = [
  { name: 'Features', href: '#features' },
  { name: 'Technology', href: '#technology' },
  { name: 'Ecosystem', href: '#ecosystem' },
  { name: 'Docs', href: '#', comingSoon: true },
];

export default function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);

  useEffect(() => {
    const handleScroll = () => {
      setIsScrolled(window.scrollY > 20);
    };
    window.addEventListener('scroll', handleScroll);
    return () => window.removeEventListener('scroll', handleScroll);
  }, []);

  return (
    <>
      <motion.nav
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
          isScrolled
            ? 'bg-[#0a0a0a]/80 backdrop-blur-xl border-b border-white/5'
            : 'bg-transparent'
        }`}
      >
        <div className="max-w-7xl mx-auto px-6 lg:px-8">
          <div className="flex items-center justify-between h-20">
            {/* Logo */}
            <Link href="/" className="flex items-center gap-3 group">
              <div className="relative">
                <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-[#26022e] to-[#3d0847] flex items-center justify-center group-hover:scale-110 transition-transform duration-300">
                  <span className="text-xl font-bold text-white">Ϙ</span>
                </div>
                <div className="absolute inset-0 rounded-xl bg-purple-500/20 blur-xl opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
              </div>
              <span className="text-xl font-semibold tracking-tight">
                SUM<span className="text-purple-400">Chain</span>
              </span>
            </Link>

            {/* Desktop Navigation */}
            <div className="hidden md:flex items-center gap-8">
              {navLinks.map((link) =>
                link.comingSoon ? (
                  <span
                    key={link.name}
                    title="Not open to public yet"
                    aria-label={`${link.name} (not open to public yet)`}
                    className="text-sm text-gray-400 cursor-not-allowed relative group"
                  >
                    {link.name}
                    <span className="pointer-events-none absolute left-full top-1/2 -translate-y-1/2 ml-2 whitespace-nowrap rounded-md bg-white/10 px-2 py-1 text-xs text-white opacity-0 group-hover:opacity-100 transition-opacity">
                      Not open to public yet
                    </span>
                  </span>
                ) : (
                  <Link
                    key={link.name}
                    href={link.href}
                    target={link.external ? '_blank' : undefined}
                    rel={link.external ? 'noopener noreferrer' : undefined}
                    className="text-sm text-gray-400 hover:text-white transition-colors duration-200 relative group"
                  >
                    {link.name}
                    <span className="absolute -bottom-1 left-0 w-0 h-0.5 bg-purple-500 group-hover:w-full transition-all duration-300" />
                  </Link>
                )
              )}
            </div>

            {/* CTA Buttons */}
            <div className="hidden md:flex items-center gap-4">
              <Link
                href="https://explorer.sum-chain.xyz"
                className="text-sm text-gray-400 hover:text-white transition-colors duration-200"
              >
                Explorer
              </Link>
              <Link
                href="#get-started"
                className="px-5 py-2.5 text-sm font-medium rounded-full bg-gradient-to-r from-[#26022e] to-[#3d0847] hover:from-[#3d0847] hover:to-[#26022e] border border-purple-500/30 hover:border-purple-500/50 transition-all duration-300 hover:shadow-lg hover:shadow-purple-500/20"
              >
                Get Started
              </Link>
            </div>

            {/* Mobile Menu Button */}
            <button
              onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
              className="md:hidden p-2 text-gray-400 hover:text-white transition-colors"
            >
              <svg
                className="w-6 h-6"
                fill="none"
                stroke="currentColor"
                viewBox="0 0 24 24"
              >
                {isMobileMenuOpen ? (
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                ) : (
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M4 6h16M4 12h16M4 18h16"
                  />
                )}
              </svg>
            </button>
          </div>
        </div>
      </motion.nav>

      {/* Mobile Menu */}
      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-40 md:hidden pt-20 bg-[#0a0a0a]/95 backdrop-blur-xl"
          >
            <div className="flex flex-col items-center gap-8 pt-12">
              {navLinks.map((link) =>
                link.comingSoon ? (
                  <span
                    key={link.name}
                    title="Not open to public yet"
                    aria-label={`${link.name} (not open to public yet)`}
                    className="text-2xl text-gray-500 cursor-not-allowed"
                  >
                    {link.name}
                    <span className="ml-2 text-xs align-middle text-gray-400">(Not open to public yet)</span>
                  </span>
                ) : (
                  <Link
                    key={link.name}
                    href={link.href}
                    target={link.external ? '_blank' : undefined}
                    onClick={() => setIsMobileMenuOpen(false)}
                    className="text-2xl text-gray-300 hover:text-white transition-colors"
                  >
                    {link.name}
                  </Link>
                )
              )}
              <Link
                href="https://explorer.sum-chain.xyz"
                className="text-2xl text-gray-300 hover:text-white transition-colors"
                onClick={() => setIsMobileMenuOpen(false)}
              >
                Explorer
              </Link>
              <Link
                href="#get-started"
                onClick={() => setIsMobileMenuOpen(false)}
                className="mt-4 px-8 py-3 text-lg font-medium rounded-full bg-gradient-to-r from-[#26022e] to-[#3d0847] border border-purple-500/30"
              >
                Get Started
              </Link>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
