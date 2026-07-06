import type { Metadata } from 'next';
import Link from 'next/link';
import { notFound } from 'next/navigation';
import Navbar from '@/components/Navbar';
import Footer from '@/components/Footer';
import { categories, getCategory, ENDPOINT } from '../_data';
import CategorySection from '../_CategorySection';

// Strip any HTML entities from a category title for plain-text metadata.
function plainTitle(title: string): string {
  return title.replace(/&amp;/g, '&').replace(/<[^>]*>/g, '');
}

export function generateStaticParams() {
  return categories.map((c) => ({ topic: c.id }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<{ topic: string }>;
}): Promise<Metadata> {
  const { topic } = await params;
  const cat = getCategory(topic);
  if (!cat) return { title: 'Docs | SUM Chain' };
  const t = plainTitle(cat.title);
  return {
    title: `${t} — JSON-RPC | SUM Chain Docs`,
    description: cat.blurb,
  };
}

export default async function DocTopicPage({
  params,
}: {
  params: Promise<{ topic: string }>;
}) {
  const { topic } = await params;
  const cat = getCategory(topic);
  if (!cat) notFound();

  return (
    <div className="min-h-screen bg-[#0a0a0a] text-white">
      <Navbar />

      <main className="relative pt-32 pb-32">
        <div className="absolute inset-0 bg-gradient-to-b from-[#0a0a0a] via-[#26022e]/20 to-[#0a0a0a]" />
        <div className="absolute inset-0 grid-pattern opacity-20" />

        <div className="relative z-10 max-w-6xl mx-auto px-6 lg:px-8">
          {/* Breadcrumb */}
          <nav className="mb-8 text-sm text-gray-500" aria-label="Breadcrumb">
            <Link href="/docs" className="text-purple-400 hover:text-purple-300">
              Docs
            </Link>
            <span className="mx-2">/</span>
            <span className="text-gray-300" dangerouslySetInnerHTML={{ __html: cat.title }} />
          </nav>

          {/* Header */}
          <div className="mb-10">
            <h1
              className="text-3xl sm:text-4xl font-bold mb-3"
              dangerouslySetInnerHTML={{ __html: cat.title }}
            />
            <p className="text-gray-400 max-w-3xl">{cat.blurb}</p>
            <p className="text-sm text-gray-500 mt-3">
              {cat.methods.length} methods · verified against the live mainnet RPC at {ENDPOINT}.
            </p>
          </div>

          {/* Topic nav (all topics; current highlighted) */}
          <div className="mb-10 flex flex-wrap gap-2">
            {categories.map((c) => (
              <Link
                key={c.id}
                href={`/docs/${c.id}`}
                aria-current={c.id === cat.id ? 'page' : undefined}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  c.id === cat.id
                    ? 'border-purple-500/50 bg-purple-500/10 text-purple-200'
                    : 'border-white/10 text-gray-400 hover:border-purple-500/30 hover:text-gray-200'
                }`}
                dangerouslySetInnerHTML={{ __html: c.title }}
              />
            ))}
          </div>

          {/* Methods */}
          <CategorySection cat={cat} />

          {/* Footer nav */}
          <div className="mt-14 flex items-center justify-between text-sm">
            <Link href="/docs" className="text-purple-400 hover:text-purple-300">
              ← All topics
            </Link>
            <a href={ENDPOINT} className="text-gray-500 hover:text-gray-300">
              {ENDPOINT}
            </a>
          </div>
        </div>
      </main>

      <Footer />
    </div>
  );
}
