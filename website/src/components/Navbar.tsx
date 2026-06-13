'use client';

import { useState } from 'react';
import { motion, AnimatePresence, useScroll, useMotionValueEvent } from 'framer-motion';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Bars3Icon, XMarkIcon } from '@heroicons/react/24/outline';

type NavLink = {
  name: string;
  href: string;
  external?: boolean;
};

const navLinks: NavLink[] = [
  { name: 'Features', href: '/#features' },
  { name: 'Technology', href: '/#technology' },
  { name: 'Ecosystem', href: '/#ecosystem' },
  { name: 'Docs', href: '/docs' },
];

export default function Navbar() {
  const [isScrolled, setIsScrolled] = useState(false);
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false);
  const pathname = usePathname();
  const { scrollY } = useScroll();

  // Motion-driven scroll state (no window scroll listener / per-frame re-render).
  useMotionValueEvent(scrollY, 'change', (y) => {
    const next = y > 20;
    setIsScrolled((prev) => (prev === next ? prev : next));
  });

  const isActive = (href: string) =>
    href.startsWith('/#') ? false : pathname === href;

  return (
    <>
      <motion.nav
        initial={{ y: -100 }}
        animate={{ y: 0 }}
        transition={{ duration: 0.6, ease: [0.22, 1, 0.36, 1] }}
        className={`fixed inset-x-0 top-0 z-50 transition-colors duration-300 ${
          isScrolled
            ? 'border-b border-[var(--border)] bg-background/80 backdrop-blur-xl'
            : 'border-b border-transparent bg-transparent'
        }`}
      >
        <div className="mx-auto max-w-6xl px-6 lg:px-8">
          <div className="flex h-[68px] items-center justify-between">
            <Link href="/" className="group flex items-center gap-3">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-brand-deep to-brand-deep-2 text-lg font-bold transition-transform duration-300 group-hover:scale-105">
                Ϙ
              </span>
              <span className="font-[family-name:var(--font-display)] text-lg font-semibold tracking-tight">
                SUM<span className="text-accent-soft">Chain</span>
              </span>
            </Link>

            <div className="hidden items-center gap-8 md:flex">
              {navLinks.map((link) => (
                <Link
                  key={link.name}
                  href={link.href}
                  aria-current={isActive(link.href) ? 'page' : undefined}
                  className={`group relative text-sm transition-colors duration-200 ${
                    isActive(link.href) ? 'text-foreground' : 'text-muted hover:text-foreground'
                  }`}
                >
                  {link.name}
                  <span
                    className={`absolute -bottom-1 left-0 h-0.5 bg-accent transition-all duration-300 ${
                      isActive(link.href) ? 'w-full' : 'w-0 group-hover:w-full'
                    }`}
                  />
                </Link>
              ))}
            </div>

            <div className="hidden items-center gap-5 md:flex">
              <Link
                href="https://explorer.sumchain.io"
                target="_blank"
                rel="noopener noreferrer"
                className="text-sm text-muted transition-colors duration-200 hover:text-foreground"
              >
                Explorer
              </Link>
              <Link
                href="/#get-started"
                className="rounded-full border border-[var(--border-strong)] px-5 py-2 text-sm font-medium text-foreground transition-colors duration-200 hover:border-accent/60 hover:bg-accent/10"
              >
                Start Building
              </Link>
            </div>

            <button
              onClick={() => setIsMobileMenuOpen((v) => !v)}
              aria-label={isMobileMenuOpen ? 'Close menu' : 'Open menu'}
              aria-expanded={isMobileMenuOpen}
              className="p-2 text-muted transition-colors hover:text-foreground md:hidden"
            >
              {isMobileMenuOpen ? (
                <XMarkIcon className="h-6 w-6" />
              ) : (
                <Bars3Icon className="h-6 w-6" />
              )}
            </button>
          </div>
        </div>
      </motion.nav>

      <AnimatePresence>
        {isMobileMenuOpen && (
          <motion.div
            initial={{ opacity: 0, y: -16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -16 }}
            transition={{ duration: 0.2 }}
            className="fixed inset-0 z-40 bg-background/95 pt-[68px] backdrop-blur-xl md:hidden"
          >
            <div className="flex flex-col items-center gap-8 pt-12">
              {navLinks.map((link) => (
                <Link
                  key={link.name}
                  href={link.href}
                  onClick={() => setIsMobileMenuOpen(false)}
                  className="text-2xl text-muted-strong transition-colors hover:text-foreground"
                >
                  {link.name}
                </Link>
              ))}
              <Link
                href="https://explorer.sumchain.io"
                target="_blank"
                rel="noopener noreferrer"
                onClick={() => setIsMobileMenuOpen(false)}
                className="text-2xl text-muted-strong transition-colors hover:text-foreground"
              >
                Explorer
              </Link>
              <Link
                href="/#get-started"
                onClick={() => setIsMobileMenuOpen(false)}
                className="mt-4 rounded-full border border-[var(--border-strong)] px-8 py-3 text-lg font-medium text-foreground"
              >
                Start Building
              </Link>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
